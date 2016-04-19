/**
 * mysqlattributeresolver.cpp
 *
 * Extension library for Shibboleth SP.
 * Resolve attributes from a MySQL database.
 */

#include "config.h"

#define MYSQLATTRIBUTERESOLVER_EXPORTS

#include <memory>

#include <boost/algorithm/string.hpp>

#include <saml/exceptions.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/SPConfig.h>
#include <shibsp/util/SPConstants.h>
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

        std::string m_connection_host;
        uint32_t m_connection_port;
        std::string m_connection_username;
        std::string m_connection_password;
        std::string m_connection_dbname;

        std::string m_query;

        std::set<std::string> m_attributes;

        // Maps a column name to the list of attributes populated by the column
        std::map<std::string,std::vector<std::string> > m_columns;

    };

    AttributeResolver* SHIBSP_DLLLOCAL MysqlAttributeResolverFactory(const xercesc::DOMElement* const & e)
    {
        return new MysqlAttributeResolver(e);
    }

};

std::vector<opensaml::Assertion*> shibsp::MysqlContext::m_assertions;

static const XMLCh connection[] = UNICODE_LITERAL_10(C,o,n,n,e,c,t,i,o,n);
static const XMLCh host[] = UNICODE_LITERAL_4(h,o,s,t);
static const XMLCh port[] = UNICODE_LITERAL_4(p,o,r,t);
static const XMLCh username[] = UNICODE_LITERAL_8(u,s,e,r,n,a,m,e);
static const XMLCh password[] = UNICODE_LITERAL_8(p,a,s,s,w,o,r,d);
static const XMLCh dbname[] = UNICODE_LITERAL_6(d,b,n,a,m,e);

static const XMLCh query[] = UNICODE_LITERAL_5(Q,u,e,r,y);

static const XMLCh column[] = UNICODE_LITERAL_6(C,o,l,u,m,n);
static const XMLCh name[] = UNICODE_LITERAL_4(n,a,m,e);
static const XMLCh attribute[] = UNICODE_LITERAL_9(a,t,t,r,i,b,u,t,e);

shibsp::MysqlAttributeResolver::MysqlAttributeResolver(const xercesc::DOMElement* e)
    : m_log(xmltooling::logging::Category::getInstance(SHIBSP_LOGCAT ".AttributeResolver.Mysql"))
{
    // Connection information
    xercesc::DOMElement* connectionElement = e ? xmltooling::XMLHelper::getFirstChildElement(e, connection) : nullptr;
    if (!connectionElement) {
        throw ConfigurationException("MySQL AttributeResolver requires <Connection> child element.");
    }

    m_connection_host = xmltooling::XMLHelper::getAttrString(connectionElement, nullptr, host);
    boost::trim(m_connection_host);
    if (m_connection_host.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires host attribute.");
    }
    m_connection_port = (uint32_t) xmltooling::XMLHelper::getAttrInt(connectionElement, 0, port);
    if (!m_connection_port) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires port attribute.");
    }
    m_connection_username = xmltooling::XMLHelper::getAttrString(connectionElement, nullptr, username);
    boost::trim(m_connection_username);
    if (m_connection_username.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires username attribute.");
    }
    m_connection_password = xmltooling::XMLHelper::getAttrString(connectionElement, nullptr, password);
    boost::trim(m_connection_password);
    if (m_connection_password.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires password attribute.");
    }
    m_connection_dbname = xmltooling::XMLHelper::getAttrString(connectionElement, nullptr, dbname);
    boost::trim(m_connection_dbname);
    if (m_connection_dbname.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires dbname attribute.");
    }

    // Query
    xercesc::DOMElement* queryElement = e ? xmltooling::XMLHelper::getFirstChildElement(e, query) : nullptr;
    xmltooling::auto_ptr_char t(queryElement ? queryElement->getTextContent(): nullptr);
    if (t.get()) {
        m_query = t.get();
        boost::trim(m_query);
    }
    if (m_query.empty()) {
        throw ConfigurationException("MySQL AttributeResolver requires <Query> element.");
    }

    // Columns
    xercesc::DOMElement* columnElement = e ? xmltooling::XMLHelper::getFirstChildElement(e, column) : nullptr;
    while (columnElement) {

        std::string columnName = xmltooling::XMLHelper::getAttrString(columnElement, nullptr, name);
        boost::trim(columnName);

        std::string attributeName = xmltooling::XMLHelper::getAttrString(columnElement, nullptr, attribute);
        boost::trim(attributeName);

        if (!(columnName.empty() || attributeName.empty())) {
            std::pair<std::set<std::string>::iterator, bool> attrResult = m_attributes.insert(attributeName);
            if (attrResult.second == false) {
                throw ConfigurationException("MySQL AttributeResolver cannot map multiple columns to the same attribute.");
            }

            std::map<std::string, std::vector<std::string> >::iterator it;
            it = m_columns.find(columnName);
            if (it == m_columns.end()) {
                std::vector<std::string> attributeList();
                std::pair<std::map<std::string, std::vector<std::string> >::iterator, bool> insertResult;
                insertResult = m_columns.insert(std::make_pair(columnName, std::vector<std::string>()));
                if (insertResult.second) {
                    it = insertResult.first;
                } else {
                    throw ConfigurationException("MySQL AttributeResolver unable to map columns to attributes.");
                }
            }
            it->second.push_back(attributeName);
        }

        columnElement = xmltooling::XMLHelper::getNextSiblingElement(columnElement, column);
    };

    if (m_columns.empty()) {
        throw ConfigurationException("MySQL AttributeResolver requires at least one <Column> element.");
    }
}


void shibsp::MysqlAttributeResolver::resolveAttributes(shibsp::ResolutionContext& ctx) const
{
    shibsp::MysqlContext& tctx = dynamic_cast<shibsp::MysqlContext&>(ctx);
    if (!tctx.getInputAttributes())
        return;
}

void shibsp::MysqlAttributeResolver::getAttributeIds(std::vector<std::string>& attributes) const
{
    for (std::set<std::string>::const_iterator it = m_attributes.begin(); it != m_attributes.end(); it++) {
        attributes.push_back(*it);
    }
}


extern "C" int MYSQLATTRIBUTERESOLVER_EXPORTS xmltooling_extension_init(void*)
{
    // Register factory functions with appropriate plugin managers in the XMLTooling/SAML/SPConfig objects.
    shibsp::SPConfig& conf = shibsp::SPConfig::getConfig();
    conf.AttributeResolverManager.registerFactory("MySQL", shibsp::MysqlAttributeResolverFactory);
    return 0;   // signal success
}

extern "C" void MYSQLATTRIBUTERESOLVER_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
