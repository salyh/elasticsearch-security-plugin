package org.elasticsearch.plugins.security.filter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.plugins.security.MalformedConfigurationException;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestChannel;
import org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerRestRequest;
import org.elasticsearch.plugins.security.http.tomcat.TomcatUserRoleCallback;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.plugins.security.util.EditableRestRequest;
import org.elasticsearch.plugins.security.util.SecurityUtil;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestStatus;

public class ActionPathFilter extends SecureRestFilter {

  public ActionPathFilter(final SecurityService securityService) {
    super(securityService);

  }

  @Override
  public void processSecure(final TomcatHttpServerRestRequest request,
      final TomcatHttpServerRestChannel channel,
      final RestFilterChain filterChain) {

    if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex( request.path(), SecurityUtil.BUILT_IN_ADMIN_COMMANDS)) {
      log.warn("Index- or Typename should not contains admin commands like " + Arrays.toString(SecurityUtil.BUILT_IN_ADMIN_COMMANDS));
    }

    if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex( request.path(), securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_READ_COMMANDS_STRICT : SecurityUtil.BUILT_IN_READ_COMMANDS_LAX)) {
      log.warn("Index- or Typename should not contains search commands like "
          + Arrays.toString(securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_READ_COMMANDS_STRICT : SecurityUtil.BUILT_IN_READ_COMMANDS_LAX));
    }

    if (SecurityUtil.stringContainsItemFromListAsTypeOrIndex( request.path(), securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_WRITE_COMMANDS_STRICT : SecurityUtil.BUILT_IN_WRITE_COMMANDS_LAX)) {
      log.warn("Index- or Typename should not contains write commands like "
          + Arrays.toString(securityService.isStrictModeEnabled()?SecurityUtil.BUILT_IN_WRITE_COMMANDS_STRICT : SecurityUtil.BUILT_IN_WRITE_COMMANDS_LAX));
    }

    try {

      final PermLevel permLevel = new PermLevelEvaluator(
          securityService.getXContentSecurityConfiguration(getType(), getId())).evaluatePerm(
            SecurityUtil.getIndices(request),
            SecurityUtil.getTypes(request),
            getClientHostAddress(request),
            new TomcatUserRoleCallback(request.getHttpServletRequest(),securityService.getSettings().get("security.ssl.userattribute")));
      
      String secondpath = null;

      try {
        secondpath = request.path().split("/")[2];
        log.debug("Second path is: "+secondpath);
      }
      catch (Exception e) {
        log.debug("Request path split failed: " + e.getMessage());
      }

      boolean evalthem;
      evalthem = true;

      if (securityService.getSettings().getAsBoolean("security.cors.enabled", false) && request.method().toString().equals("OPTIONS")) { 
        evalthem = false;
      } else if (securityService.getSettings().getAsBoolean("security.module.kibana.special", false) && request.path().equals("/_nodes")) { 
        evalthem = false;
      } else if (securityService.getSettings().getAsBoolean("security.module.kibana.special", false) && secondpath.equals("_aliases")) { 
        evalthem = false;
      } else if (securityService.getSettings().getAsBoolean("security.module.kibana.special", false) && secondpath.equals("_mapping")) { 
        evalthem = false;
      }

      if (secondpath != null) {
        if ( securityService.getSettings().getAsBoolean("security.module.kibana.special", false) && 
            permLevel.ordinal() >= PermLevel.READONLY.ordinal() && secondpath.equals("_search") && SecurityUtil.isReadRequest(request,securityService.isStrictModeEnabled()) ) {
          evalthem = false;
        }
      }

      if (evalthem) {

        if ( !securityService.getSettings().getAsBoolean("security.module.kibana.special", false) ) {
        log.debug("Evaluate the returned permissions");

          if (permLevel == PermLevel.NONE) {
            SecurityUtil.send(request, channel, RestStatus.FORBIDDEN, "No permission (at all)");
            return;
          }

          if (permLevel.ordinal() < PermLevel.ALL.ordinal() && SecurityUtil.isAdminRequest(request)) {
            SecurityUtil.send(request, channel, RestStatus.FORBIDDEN, "No permission (for admin actions)");
            return;
          }

          if (permLevel.ordinal() < PermLevel.READWRITE.ordinal() && SecurityUtil.isWriteRequest(request,securityService.isStrictModeEnabled())) {
            SecurityUtil.send(request, channel, RestStatus.FORBIDDEN, "No permission (for write actions)");
            return;
          }

          if (permLevel == PermLevel.READONLY && !SecurityUtil.isReadRequest(request,securityService.isStrictModeEnabled())) {
            SecurityUtil.send(request, channel, RestStatus.FORBIDDEN, "No permission (for read actions)");
            return;
          }

        }

        modifiyKibanaRequest(request, channel);
      
      }

      filterChain.continueProcessing(request, channel);
      return;

    } catch (final MalformedConfigurationException e) {
      log.error("Cannot parse security configuration ", e);
      SecurityUtil.send(request, channel, RestStatus.INTERNAL_SERVER_ERROR, "Cannot parse security configuration");

      return;

    } catch (final Exception e) {
      log.error("Generic error: ", e);
      SecurityUtil.send(request, channel, RestStatus.INTERNAL_SERVER_ERROR, "Generic error, see log for details");

      return;
    }

  }
  
  /**
   * Method added to modify the request on the fly to
   * allow it to process generic queries coming from kibana by
   * validating against the security framework (contributed by Ram Kotamaraja)
   * @param request
   */
  private void modifiyKibanaRequest(
      final TomcatHttpServerRestRequest request,
      final TomcatHttpServerRestChannel channel) {

    List<String> reqTypesList = SecurityUtil.getTypes(request);
    if (reqTypesList != null && !reqTypesList.isEmpty() && reqTypesList.size() > 0) {
      log.debug("Not modifying the request (for kibana) as there is one or more types already associated with the request");
      reqTypesList = null;
      return;
    }

    String kibanaPermLevel = null;
    try {
      kibanaPermLevel = securityService.getXContentSecurityConfiguration(getType(), getKibanaId());
    } catch (Exception e) {
      log.debug("No Kibana configuration found, so continuing the rest of the process: " + e.getMessage());
      return;
    }

    List<String> kibanaTypesList = null;
    List<String> authorizedTypesList = new ArrayList<String>();
    try {
      if (kibanaPermLevel != null && kibanaPermLevel.length() > 0) {
        kibanaTypesList = securityService.getKibanaTypes(SecurityUtil.getIndices(request));
      }

      final String reqContent = request.content().toUtf8();
      String modifiedContent = reqContent;

      List<String> requestTypes = SecurityUtil.getTypes(request);

      if (requestTypes == null || requestTypes.isEmpty() || requestTypes.size() == 0) {
        log.debug("Allowed Kibana Types are: " + kibanaTypesList);
        if (kibanaTypesList != null || !kibanaTypesList.isEmpty()) {

          Iterator<String> kibanaTypesItr = kibanaTypesList.iterator();

          while (kibanaTypesItr.hasNext()) {

            List<String> kibanaType = new ArrayList<String>();
            kibanaType.add((String) kibanaTypesItr.next());
            //At this point we have widdled down the search request, extracted the index and types.
            //Since a kibana request is _search, it has no types, so we've extracted them and now must cross check real access against permLevel 
            log.debug("Kibana perms checked for index: " + SecurityUtil.getIndices(request) + " and types: " + kibanaType);
            final PermLevel permLevel = new PermLevelEvaluator(securityService.getXContentSecurityConfiguration(getType(), getId())).evaluatePerm(
              SecurityUtil.getIndices(request),
              kibanaType,
              getClientHostAddress(request),
              new TomcatUserRoleCallback(request.getHttpServletRequest(),securityService.getSettings().get("security.ssl.userattribute"))
            );

            log.debug("Kibana artificial perm level is: " + permLevel);

            if (!permLevel.equals(PermLevel.NONE)) {
              authorizedTypesList.addAll(kibanaType);
            }
          }

          //log.debug("Processing kibana types "+ kibanaTypesList);
          log.debug("request Content = "+ reqContent);

          String kibanaFilterStarter = "\"must\":[";
          int beginIndex = reqContent.indexOf(kibanaFilterStarter);
          
          if (beginIndex > 0) {
            String preReqContent = reqContent.substring(0, beginIndex + kibanaFilterStarter.length());
            String postReqContent = reqContent.substring(beginIndex + kibanaFilterStarter.length());

            modifiedContent = preReqContent + "{\"or\": {\"filters\":[";

            if (authorizedTypesList != null) {
              Iterator<String> authorizedTypesItr = authorizedTypesList.iterator();
              while (authorizedTypesItr.hasNext()) {
                modifiedContent += "{\"type\":{\"value\":\"" + authorizedTypesItr.next().toString() + "\"}},";
              }
              modifiedContent = modifiedContent.substring(0, modifiedContent.length() - 1);
            }

            modifiedContent += "]}}," + postReqContent;
            log.debug("modified request content = " + modifiedContent);
                        
            request.setContent(new BytesArray(modifiedContent));
            request.setAttribute(TomcatHttpServerRestRequest.REQUEST_CONTENT_ATTRIBUTE, request.getContent());

          }
        }
      }
    } catch (MalformedConfigurationException e) {
      log.error("Cannot parse security configuration ", e);
      SecurityUtil.send(request, channel, RestStatus.INTERNAL_SERVER_ERROR, "Cannot parse security configuration");

      return;

    } catch (Exception e) {
      log.error("Generic error: ", e);
      SecurityUtil.send(request, channel, RestStatus.INTERNAL_SERVER_ERROR, "Generic error, see log for details");

      return;

    }

  }

  /**
  * Method to return the default id (contributed by Ram Kotamaraja)
  * @return String - default id string
  */
  protected String getKibanaId() {
    return "kibana";
  }

  @Override
  protected String getType() {
    return "actionpathfilter";
  }

  @Override
  protected String getId() {
    return "actionpathfilter";
  }

}
