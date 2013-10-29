package org.elasticsearch.plugins.security;

import java.util.Collection;

import org.elasticsearch.common.collect.Lists;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.plugins.security.service.SecurityService;

public class SecurityPlugin extends AbstractPlugin {

	private final ESLogger log = Loggers.getLogger(this.getClass());

	public SecurityPlugin() {
		this.log.debug("Starting Security Plugin");
	}

	@SuppressWarnings("rawtypes")
	    @Override 
	    public Collection<Class<? extends LifecycleComponent>> services() {
	        Collection<Class<? extends LifecycleComponent>> services = Lists.newArrayList();
	
	        
	            services.add(SecurityService.class);
	        
	        return services;
	   }
	
	
	

	@Override
	public String description() {
		return "Security Plugin";
	}

	@Override
	public String name() {
		return "elasticsearch-security-plugin";
	}

}
