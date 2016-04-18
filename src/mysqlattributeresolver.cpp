/**
 * mysqlattributeresolver.cpp
 *
 * Extension library for Shibboleth SP.
 * Resolve attributes from a MySQL database.
 */

#include "config.h"

#define MYSQLATTRIBUTERESOLVER_EXPORTS

#include <memory>

#include <saml/exceptions.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/SessionCache.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>


namespace shibsp {

    class SHIBSP_DLLLOCAL MysqlContext : public ResolutionContext
    {
    public:
        MysqlContext(const std::vector<Attribute*>* attributes) : m_inputAttributes(attributes) {
        }

        ~MysqlContext() {
            std::for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
        }

        const std::vector<Attribute*>* getInputAttributes() const {
            return m_inputAttributes;
        }

        std::vector<Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }

        std::vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const std::vector<Attribute*>* m_inputAttributes;
        std::vector<Attribute*> m_attributes;
        static std::vector<opensaml::Assertion*> m_assertions;   // empty dummy
    };


    class SHIBSP_DLLLOCAL MysqlAttributeResolver : public AttributeResolver
    {
    public:
        MysqlAttributeResolver(const xercesc::DOMElement* e);
        virtual ~MysqlAttributeResolver() {}

        Lockable* lock() {
            return this;
        }

        void unlock() {
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const XMLCh* protocol,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const std::vector<const opensaml::Assertion*>* tokens=nullptr,
            const std::vector<Attribute*>* attributes=nullptr
            ) const {
            return createResolutionContext(application, nullptr, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const xmltooling::GenericRequest* request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const XMLCh* protocol,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const std::vector<const opensaml::Assertion*>* tokens=nullptr,
            const std::vector<Attribute*>* attributes=nullptr
            ) const {
            return new MysqlContext(attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new MysqlContext(&session.getAttributes());
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(std::vector<std::string>& attributes) const;

    private:
        xmltooling::logging::Category& m_log;
    };

    AttributeResolver* SHIBSP_DLLLOCAL MysqlAttributeResolverFactory(const xercesc::DOMElement* const & e)
    {
        return new MysqlAttributeResolver(e);
    }

};

std::vector<opensaml::Assertion*> shibsp::MysqlContext::m_assertions;

shibsp::MysqlAttributeResolver::MysqlAttributeResolver(const xercesc::DOMElement* e)
    : m_log(xmltooling::logging::Category::getInstance(SHIBSP_LOGCAT ".AttributeResolver.Mysql"))
{

}


void shibsp::MysqlAttributeResolver::resolveAttributes(shibsp::ResolutionContext& ctx) const
{
    shibsp::MysqlContext& tctx = dynamic_cast<shibsp::MysqlContext&>(ctx);
    if (!tctx.getInputAttributes())
        return;
}

void shibsp::MysqlAttributeResolver::getAttributeIds(std::vector<std::string>& attributes) const {

}


extern "C" int MYSQLATTRIBUTERESOLVER_EXPORTS xmltooling_extension_init(void*)
{
    // Register factory functions with appropriate plugin managers in the XMLTooling/SAML/SPConfig objects.
    return 0;   // signal success
}

extern "C" void MYSQLATTRIBUTERESOLVER_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
