package net.bull.javamelody;

import static net.bull.javamelody.HttpParameters.COLLECTOR_PARAMETER;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;



/**
 * Filtre de servlet pour le monitoring.
 * C'est la classe de ce filtre qui doit être déclarée dans le fichier web.xml de la webapp.
 * 
 * Modif OSIVIA (base java melody 1.0.37)
 * - suppression de la requete wrappee
 * - nettoyage des urls (/auth, /pagemarker)
 * - initialisation de la réponse (type mime, encodage)
 * 
 * @author Emeric Vernat
 */
public class AdaptedMonitoringFilter implements Filter {

    private static boolean instanceCreated;

    private static final List<String> CONTEXT_PATHS = new ArrayList<String>();

    private boolean instanceEnabled;

    // Ces variables httpCounter et errorCounter conservent un état qui est global au filtre
    // et à l'application (donc thread-safe).
    private Counter httpCounter;
    private Counter errorCounter;

    private boolean monitoringDisabled;
    private boolean logEnabled;
    private Pattern urlExcludePattern;
    private Pattern allowedAddrPattern;
    private FilterContext filterContext;
    private FilterConfig filterConfig;
    private String monitoringUrl;
    
    protected static final Log logger = LogFactory.getLog(AdaptedMonitoringFilter.class);

    /**
     * Constructeur.
     */
    public AdaptedMonitoringFilter() {
        super();
        if (instanceCreated) {
            // ce filter a déjà été chargé précédemment et est chargé une 2ème fois donc on désactive cette 2ème instance
            // (cela peut arriver par exemple dans glassfish v3 lorsque le filter est déclaré dans le fichier web.xml
            // et déclaré par ailleurs dans le fichier web-fragment.xml à l'intérieur du jar, issue 147),
            // mais il peut être réactivé dans init (issue 193)
            this.instanceEnabled = false;
        } else {
            this.instanceEnabled = true;
            setInstanceCreated(true);
        }
    }

    private static void setInstanceCreated(boolean newInstanceCreated) {
        instanceCreated = newInstanceCreated;
    }

    /** {@inheritDoc} */
    public void init(FilterConfig config) throws ServletException {
        final String contextPath = Parameters.getContextPath(config.getServletContext());
        if (!this.instanceEnabled) {
            if (!CONTEXT_PATHS.contains(contextPath)) {
                // si jars dans tomcat/lib, il y a plusieurs instances mais dans des webapps différentes (issue 193)
                this.instanceEnabled = true;
            } else {
                return;
            }
        }
        CONTEXT_PATHS.add(contextPath);
        this.filterConfig = config;
        Parameters.initialize(config);
        this.monitoringDisabled = Boolean.parseBoolean(Parameters.getParameter(Parameter.DISABLED));
        if (this.monitoringDisabled) {
            return;
        }

        LOG.debug("JavaMelody filter init started");

        this.filterContext = new FilterContext();
        final Collector collector = this.filterContext.getCollector();
        this.httpCounter = collector.getCounterByName(Counter.HTTP_COUNTER_NAME);
        this.errorCounter = collector.getCounterByName(Counter.ERROR_COUNTER_NAME);

        this.logEnabled = Boolean.parseBoolean(Parameters.getParameter(Parameter.LOG));
        if (Parameters.getParameter(Parameter.URL_EXCLUDE_PATTERN) != null) {
            // lance une PatternSyntaxException si la syntaxe du pattern est invalide
            this.urlExcludePattern = Pattern.compile(Parameters.getParameter(Parameter.URL_EXCLUDE_PATTERN));
        }
        if (Parameters.getParameter(Parameter.ALLOWED_ADDR_PATTERN) != null) {
            this.allowedAddrPattern = Pattern.compile(Parameters.getParameter(Parameter.ALLOWED_ADDR_PATTERN));
        }

        LOG.debug("JavaMelody filter init done");
    }

    /** {@inheritDoc} */
    public void destroy() {
        if (this.monitoringDisabled || !this.instanceEnabled) {
            return;
        }
        try {
            if (this.filterContext != null) {
                this.filterContext.destroy();
            }
        } finally {
            // nettoyage avant le retrait de la webapp au cas où celui-ci ne suffise pas
            this.httpCounter = null;
            this.errorCounter = null;
            this.urlExcludePattern = null;
            this.allowedAddrPattern = null;
            this.filterConfig = null;
            this.filterContext = null;
        }
    }

    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse) || this.monitoringDisabled || !this.instanceEnabled) {
            // si ce n'est pas une requête http ou si le monitoring est désactivé, on fait suivre
            chain.doFilter(request, response);
            return;
        }
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (httpRequest.getRequestURI().equals(this.getMonitoringUrl(httpRequest))) {
            this.doMonitoring(httpRequest, httpResponse);
            return;
        }
        if (!this.httpCounter.isDisplayed() || this.isRequestExcluded((HttpServletRequest) request)) {
            // si cette url est exclue ou si le counter http est désactivé, on ne monitore pas cette requête http
            chain.doFilter(request, response);
            return;
        }

        this.doFilter(chain, httpRequest, httpResponse);
    }

    private void doFilter(FilterChain chain, HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException, ServletException {
        // HttpServletRequest wrappedRequest = JspWrapper.createHttpRequestWrapper(httpRequest);
        if ((httpRequest.getContentType() != null) && httpRequest.getContentType().startsWith("text/x-gwt-rpc")) {
            // wrappedRequest = new GWTRequestWrapper(wrappedRequest);
        }
        final CounterServletResponseWrapper wrappedResponse = new CounterServletResponseWrapper(httpResponse);

        wrappedResponse.setCharacterEncoding("UTF-8");
        wrappedResponse.setContentType("text/html;charset=UTF-8");        
        final long start = System.currentTimeMillis();
        final long startCpuTime = ThreadInformations.getCurrentThreadCpuTime();
        boolean systemError = false;
        Throwable systemException = null;
        String requestName = this.getRequestName(httpRequest);
        final String completeRequestName = getCompleteRequestName(httpRequest, true);
        try {
            JdbcWrapper.ACTIVE_THREAD_COUNT.incrementAndGet();
            // on binde le contexte de la requête http pour les requêtes sql
            this.httpCounter.bindContext(requestName, completeRequestName, httpRequest.getRemoteUser(), startCpuTime);
            // on binde la requête http (utilisateur courant et requête complète) pour les derniers logs d'erreurs
            httpRequest.setAttribute(CounterError.REQUEST_KEY, completeRequestName);
            CounterError.bindRequest(httpRequest);
            chain.doFilter(httpRequest, wrappedResponse);
             
            wrappedResponse.flushBuffer();
        } catch (final Throwable t) { // NOPMD
            // on catche Throwable pour avoir tous les cas d'erreur système
            systemException = t;
            throwException(t);
        } finally {
            try {
                // Si la durée est négative (arrive bien que rarement en cas de synchronisation d'horloge système),
                // alors on considère que la durée est 0.

                // Rq : sous Windows XP, currentTimeMillis a une résolution de 16ms environ
                // (discrètisation de la durée en 0, 16 ou 32 ms, etc ...)
                // et sous linux ou Windows Vista la résolution est bien meilleure.
                // On n'utilise pas nanoTime car il peut être un peu plus lent (mesuré à 2 microsecondes,
                // voir aussi http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6440250)
                // et car des millisecondes suffisent pour une requête http
                final long duration = Math.max(System.currentTimeMillis() - start, 0);
                final long cpuUsedMillis = (ThreadInformations.getCurrentThreadCpuTime() - startCpuTime) / 1000000;

                JdbcWrapper.ACTIVE_THREAD_COUNT.decrementAndGet();

                this.putUserInfoInSession(httpRequest);

                if (systemException != null) {
                    systemError = true;
                    final StringWriter stackTrace = new StringWriter(200);
                    systemException.printStackTrace(new PrintWriter(stackTrace));
                    this.errorCounter.addRequestForSystemError(systemException.toString(), duration, cpuUsedMillis, stackTrace.toString());
                } else if (wrappedResponse.getCurrentStatus() >= 400) {
                    systemError = true;
                    this.errorCounter.addRequestForSystemError("Error" + wrappedResponse.getCurrentStatus(), duration, cpuUsedMillis, null);
                }

                // taille du flux sortant
                final int responseSize = wrappedResponse.getDataLength();
                // nom identifiant la requête
                if (wrappedResponse.getCurrentStatus() == HttpServletResponse.SC_NOT_FOUND) {
                    // Sécurité : si status http est 404, alors requestName est Error404
                    // pour éviter de saturer la mémoire avec potentiellement beaucoup d'url différentes
                    requestName = "Error404";
                }

                // on enregistre la requête dans les statistiques
                this.httpCounter.addRequest(requestName, duration, cpuUsedMillis, systemError, responseSize);
                // on log sur Log4J ou java.util.logging dans la catégorie correspond au nom du filtre dans web.xml
                this.log(httpRequest, requestName, duration, systemError, responseSize);
            } finally {
                // normalement le unbind du contexte a été fait dans httpCounter.addRequest
                // mais pour être sûr au cas où il y ait une exception comme OutOfMemoryError
                // on le refait ici pour éviter des erreurs par la suite,
                // car il ne doit pas y avoir de contexte restant au delà de la requête http
                this.httpCounter.unbindContext();
                // et unbind de la requête http
                CounterError.unbindRequest();
            }
        }
    }

    protected String getRequestName(HttpServletRequest request) {
        String url = getCompleteRequestName(request, false);

        Pattern pattern = Pattern.compile("(/auth)?(/pagemarker/([^/])*)?((.*))");

        Matcher mURL = pattern.matcher(url);

        if (mURL.matches()) {
            url = mURL.group(mURL.groupCount() - 1);
        }

        return url;
    }

    protected final String getMonitoringUrl(HttpServletRequest httpRequest) {
        if (this.monitoringUrl == null) {
            final String parameterValue = Parameters.getParameter(Parameter.MONITORING_PATH);
            if (parameterValue == null) {
                this.monitoringUrl = httpRequest.getContextPath() + "/monitoring";
            } else {
                this.monitoringUrl = httpRequest.getContextPath() + parameterValue;
            }
        }
        return this.monitoringUrl;
    }

    private void putUserInfoInSession(HttpServletRequest httpRequest) {
        final HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            // la session n'est pas encore créée (et ne le sera peut-être jamais)
            return;
        }
        // on ne met dans la session ces attributs que si ils n'y sont pas déjà
        // (pour que la session ne soit pas resynchronisée si serveur en cluster par exemple),
        // donc l'adresse ip est celle de la première requête créant une session,
        // et si l'adresse ip change ensuite c'est très étrange
        // mais elle n'est pas mise à jour dans la session
        if (session.getAttribute(SessionInformations.SESSION_COUNTRY_KEY) == null) {
            // langue préférée du navigateur, getLocale ne peut être null
            final Locale locale = httpRequest.getLocale();
            if (locale.getCountry().length() > 0) {
                session.setAttribute(SessionInformations.SESSION_COUNTRY_KEY, locale.getCountry());
            } else {
                session.setAttribute(SessionInformations.SESSION_COUNTRY_KEY, locale.getLanguage());
            }
        }
        if (session.getAttribute(SessionInformations.SESSION_REMOTE_ADDR) == null) {
            // adresse ip
            final String forwardedFor = httpRequest.getHeader("X-Forwarded-For");
            final String remoteAddr;
            if (forwardedFor == null) {
                remoteAddr = httpRequest.getRemoteAddr();
            } else {
                remoteAddr = httpRequest.getRemoteAddr() + " forwarded for " + forwardedFor;
            }
            session.setAttribute(SessionInformations.SESSION_REMOTE_ADDR, remoteAddr);
        }
        if (session.getAttribute(SessionInformations.SESSION_REMOTE_USER) == null) {
            // login utilisateur, peut être null
            final String remoteUser = httpRequest.getRemoteUser();
            if (remoteUser != null) {
                session.setAttribute(SessionInformations.SESSION_REMOTE_USER, remoteUser);
            }
        }
    }

    private void doMonitoring(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
        if (this.isRequestNotAllowed(httpRequest)) {
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden access");
            return;
        }
        final Collector collector = this.filterContext.getCollector();
        final MonitoringController monitoringController = new MonitoringController(collector, null);
        monitoringController.executeActionIfNeeded(httpRequest);
        // javaInformations doit être réinstanciée et doit être après executeActionIfNeeded
        // pour avoir des informations à jour
        final JavaInformations javaInformations;
        if (MonitoringController.isJavaInformationsNeeded(httpRequest)) {
            javaInformations = new JavaInformations(this.filterConfig.getServletContext(), true);
        } else {
            javaInformations = null;
        }
        monitoringController.doReport(httpRequest, httpResponse, Collections.singletonList(javaInformations));

        if ("stop".equalsIgnoreCase(httpRequest.getParameter(COLLECTOR_PARAMETER))) {
            // on a été appelé par un serveur de collecte qui fera l'aggrégation dans le temps,
            // le stockage et les courbes, donc on arrête le timer s'il est démarré
            // et on vide les stats pour que le serveur de collecte ne récupère que les deltas
            if (this.filterContext.getTimer() != null) {
                this.filterContext.getTimer().cancel();
            }
            collector.stop();
        }
    }

    private static String getCompleteRequestName(HttpServletRequest httpRequest, boolean includeQueryString) {
        // on ne prend pas httpRequest.getPathInfo()
        // car requestURI == <context>/<servlet>/<pathInfo>,
        // et dans le cas où il y a plusieurs servlets (par domaine fonctionnel ou technique)
        // pathInfo ne contient pas l'indication utile de la servlet
        String tmp = httpRequest.getRequestURI().substring(httpRequest.getContextPath().length());
        // si la requête http contient un ";", par exemple ";jsessionid=12345567890ABCDEF"
        // quand le navigateur web n'accepte pas les cookies, alors on ignore ce qu'il y a à partir de ";"
        // et on ne garde que la requête http elle-même
        final int lastIndexOfSemiColon = tmp.lastIndexOf(';');
        if (lastIndexOfSemiColon != -1) {
            tmp = tmp.substring(0, lastIndexOfSemiColon);
        }
        final String method;
        if ("XMLHttpRequest".equals(httpRequest.getHeader("X-Requested-With"))) {
            method = "ajax " + httpRequest.getMethod();
        } else {
            method = httpRequest.getMethod();
        }
        if (!includeQueryString) {
            // 20091201 dhartford:Check for GWT for modified http request statistic gathering.
            if (httpRequest instanceof GWTRequestWrapper) {
                // Cast the GWT HttpServletRequestWrapper object, get the actual payload for
                // type x-gwt-rpc, and obtain methodname (manually, the 7th pipe-delimited item).
                final GWTRequestWrapper wrapper = (GWTRequestWrapper) httpRequest;
                return tmp + '.' + wrapper.getGwtRpcMethodName() + " GWT-RPC";
            }

            return tmp + ' ' + method;
        }
        final String queryString = httpRequest.getQueryString();
        if (queryString == null) {
            return tmp + ' ' + method;
        }
        return tmp + '?' + queryString + ' ' + method;
    }

    private boolean isRequestExcluded(HttpServletRequest httpRequest) {
        return (this.urlExcludePattern != null)
                && this.urlExcludePattern.matcher(httpRequest.getRequestURI().substring(httpRequest.getContextPath().length())).matches();
    }

    private boolean isRequestNotAllowed(HttpServletRequest httpRequest) {
        return (this.allowedAddrPattern != null) && !this.allowedAddrPattern.matcher(httpRequest.getRemoteAddr()).matches();
    }

    // cette méthode est protected pour pouvoir être surchargée dans une classe définie par l'application
    protected void log(HttpServletRequest httpRequest, String requestName, long duration, boolean systemError, int responseSize) {
        if (!this.logEnabled) {
            return;
        }
        final String filterName = this.filterConfig.getFilterName();
        LOG.logHttpRequest(httpRequest, requestName, duration, systemError, responseSize, filterName);
    }

    private static void throwException(Throwable t) throws IOException, ServletException {
        if (t instanceof Error) {
            throw (Error) t;
        } else if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
        } else if (t instanceof IOException) {
            throw (IOException) t;
        } else if (t instanceof ServletException) {
            throw (ServletException) t;
        } else {
            // n'arrive à priori pas car chain.doFilter ne déclare que IOException et ServletException
            // mais au cas où
            throw new ServletException(t.getMessage(), t);
        }
    }

    FilterContext getFilterContext() {
        return this.filterContext;
    }
}

