package it.pleaseopen.authenticator.filterip;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class FilterIPAuthenticatorFactory implements AuthenticatorFactory {
    @Override
    public String getDisplayType() {
        return "Filter by IP";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Filter authentication by IP address";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        providerConfigProperty.setName("Allowed IPs");
        providerConfigProperty.setLabel("List of IP address allowed");
        providerConfigProperty.setHelpText("Each IP listed will be allowed, all other results to an authentication failed. Ranges are allowed separated by a '-' ");
        providerConfigProperty.setDefaultValue("127.0.0.1");
        List<ProviderConfigProperty> providerConfigProperties = new ArrayList<>();
        providerConfigProperties.add(providerConfigProperty);
        return providerConfigProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new FilterIPAuthenticator(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "filterIP";
    }
}
