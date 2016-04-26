/**
 * mysqlattributeresolver.cpp
 *
 * Extension library for Shibboleth SP.
 * Resolve attributes from a MySQL database.
 */

#include "config.h"

#define MYSQLATTRIBUTERESOLVER_EXPORTS

#include <algorithm>
#include <memory>
#include <regex.h>

#include <boost/algorithm/string.hpp>

#include <saml/exceptions.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/SPConfig.h>
#include <shibsp/util/SPConstants.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>

#include <mysql.h>


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
        std::vector<std::string> m_query_bind_attributes;

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
    xercesc::DOMElement* connection_element = e ? xmltooling::XMLHelper::getFirstChildElement(e, connection) : nullptr;
    if (!connection_element) {
        throw ConfigurationException("MySQL AttributeResolver requires <Connection> child element.");
    }

    m_connection_host = xmltooling::XMLHelper::getAttrString(connection_element, nullptr, host);
    boost::trim(m_connection_host);
    if (m_connection_host.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires host attribute.");
    }
    m_connection_port = (uint32_t) xmltooling::XMLHelper::getAttrInt(connection_element, 0, port);
    if (!m_connection_port) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires port attribute.");
    }
    m_connection_username = xmltooling::XMLHelper::getAttrString(connection_element, nullptr, username);
    boost::trim(m_connection_username);
    if (m_connection_username.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires username attribute.");
    }
    m_connection_password = xmltooling::XMLHelper::getAttrString(connection_element, nullptr, password);
    boost::trim(m_connection_password);
    if (m_connection_password.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires password attribute.");
    }
    m_connection_dbname = xmltooling::XMLHelper::getAttrString(connection_element, nullptr, dbname);
    boost::trim(m_connection_dbname);
    if (m_connection_dbname.empty()) {
        throw ConfigurationException("MySQL AttributeResolver's <Connection> element requires dbname attribute.");
    }

    // Query
    xercesc::DOMElement* query_element = e ? xmltooling::XMLHelper::getFirstChildElement(e, query) : nullptr;
    xmltooling::auto_ptr_char t(query_element ? query_element->getTextContent(): nullptr);
    if (t.get()) {
        m_query = t.get();
        boost::trim(m_query);
    }
    if (m_query.empty()) {
        throw ConfigurationException("MySQL AttributeResolver requires <Query> element.");
    }

    regex_t param_regex;
    if (regcomp(&param_regex, "=\\s*\\$([A-Za-z0-9]+)", REG_EXTENDED)) {
        throw ConfigurationException("Unable to compile query parameter regular expression.");
    }

    regmatch_t match_groups[2];
    int32_t match_return = regexec(&param_regex, m_query.c_str(), 2, match_groups, 0);
    while (match_return == 0) {
        std::string param_attr_name = m_query.substr(match_groups[1].rm_so, match_groups[1].rm_eo);
        m_query_bind_attributes.push_back(param_attr_name);

        m_query.erase(match_groups[1].rm_so, match_groups[1].rm_eo - match_groups[1].rm_so);
        m_query.replace(match_groups[1].rm_so - 1, 1, "?");

        match_return = regexec(&param_regex, m_query.c_str(), 2, match_groups, 0);
    }

    regfree(&param_regex);

    // Columns
    xercesc::DOMElement* column_element = e ? xmltooling::XMLHelper::getFirstChildElement(e, column) : nullptr;
    while (column_element) {

        std::string column_name = xmltooling::XMLHelper::getAttrString(column_element, nullptr, name);
        boost::trim(column_name);

        std::string attr_name = xmltooling::XMLHelper::getAttrString(column_element, nullptr, attribute);
        boost::trim(attr_name);

        if (!(column_name.empty() || attr_name.empty())) {
            auto insert_attr_result = m_attributes.insert(attr_name);
            if (insert_attr_result.second == false) {
                throw ConfigurationException("MySQL AttributeResolver cannot map multiple columns to the same attribute.");
            }

            auto col_and_attrs = m_columns.find(column_name);
            if (col_and_attrs == m_columns.end()) {
                auto insert_result = m_columns.insert(std::make_pair(column_name, std::vector<std::string>()));
                if (insert_result.second) {
                    col_and_attrs = insert_result.first;
                } else {
                    throw ConfigurationException("MySQL AttributeResolver unable to map columns to attributes.");
                }
            }
            col_and_attrs->second.push_back(attr_name);
        }

        column_element = xmltooling::XMLHelper::getNextSiblingElement(column_element, column);
    };

    if (m_columns.empty()) {
        throw ConfigurationException("MySQL AttributeResolver requires at least one <Column> element.");
    }

    m_log.info("Query = %s", m_query.c_str());
    for (auto attr_name : m_query_bind_attributes) {
        m_log.info("Bind attribute: %s", attr_name.c_str());
    }

    for (auto attr_name : m_attributes) {
        m_log.info("Resolves %s attribute", attr_name.c_str());
    }

    for (auto col_and_attrs : m_columns) {
        for (auto attr_name : col_and_attrs.second) {
            m_log.info("Column %s -> attribute %s", col_and_attrs.first.c_str(), attr_name.c_str());
        }
    }
}


void shibsp::MysqlAttributeResolver::resolveAttributes(shibsp::ResolutionContext& ctx) const
{
    shibsp::MysqlContext& mctx = dynamic_cast<shibsp::MysqlContext&>(ctx);
    if (!mctx.getInputAttributes()) {
        return;
    }

    // Create a map of attribute name to attribute for all attributes that are used as query parameters
    std::map<std::string,const shibsp::Attribute*> attrmap;
    for (auto attr_name : m_query_bind_attributes) {
        auto attr_id_matches = [attr_name] (shibsp::Attribute* a) { return attr_name == a->getId(); };
        auto attr = std::find_if(mctx.getInputAttributes()->begin(), mctx.getInputAttributes()->end(), attr_id_matches);
        if (attr == mctx.getInputAttributes()->end()) {
            m_log.warn("Query parameter attribute (%s) missing", attr_name.c_str());
            return;
        }
        else if (!attrmap.empty() && (*attr)->valueCount() != attrmap.begin()->second->valueCount()) {
            m_log.warn("All query parameter attributes must contain equal number of values");
            return;
        }
        attrmap[attr_name] = *attr;
    }

    MYSQL* db_connection = nullptr;
    db_connection = mysql_init(db_connection);
    if (!db_connection) {
        m_log.error("Failed to initialize database connection.");
        return;
    }

    if (!mysql_real_connect(db_connection,
            m_connection_host.c_str(),
            m_connection_username.c_str(),
            m_connection_password.c_str(),
            m_connection_dbname.c_str(),
            m_connection_port,
            NULL, 0)
    ) {
        m_log.error("Failed to connect to database: %s", mysql_error(db_connection));
        return;
    }

    MYSQL_STMT* stmt = nullptr;
    stmt = mysql_stmt_init(db_connection);
    if (!stmt) {
        m_log.error("Failed to initialize statement: %s", mysql_stmt_error(stmt));
        mysql_close(db_connection);
        return;
    }

    if (mysql_stmt_prepare(stmt, m_query.c_str(), m_query.length()) != 0) {
        m_log.error("Failed to prepare statement: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(db_connection);
        return;
    }

    uint32_t num_params = m_query_bind_attributes.size();
    MYSQL_BIND* bind_params = new MYSQL_BIND[num_params];
    unsigned long* bind_params_length = new unsigned long[num_params];
    my_bool* bind_params_is_null = new my_bool[num_params];
    memset(bind_params_is_null, 0, num_params * sizeof(my_bool));
    my_bool* bind_params_error = new my_bool[num_params];

    for (uint32_t i = 0; i < num_params; i++) {
        bind_params[i].buffer_type = MYSQL_TYPE_STRING;
        auto a = attrmap.find(m_query_bind_attributes[i]);
        if (a == attrmap.end()) {
            m_log.warn("No '%s' attribute found to bind to query", m_query_bind_attributes[i].c_str());
        } else {
            if (a->second->getSerializedValues().empty()) {
                m_log.warn("'%s' attribute has no value to bind to query", m_query_bind_attributes[i].c_str());
            } else {
                std::string attr_value = a->second->getSerializedValues().at(0);
                m_log.info("Binding '%s' to %s", attr_value.c_str(), m_query_bind_attributes[i].c_str());
                bind_params[i].buffer = (void *) attr_value.c_str();
                bind_params[i].buffer_length = attr_value.length();
                bind_params_length[i] = attr_value.length();
            }
        }
        bind_params[i].is_null = &bind_params_is_null[i];
        m_log.info("%d", bind_params_is_null[i]);
        bind_params[i].error = &bind_params_error[i];
        bind_params[i].length = &bind_params_length[i];
    }

    if (mysql_stmt_bind_param(stmt, bind_params) != 0) {
        m_log.warn("Failed to bind parameters: %s", mysql_stmt_error(stmt));
    } else {
        if (mysql_stmt_execute(stmt) != 0) {
            m_log.warn("Failed to execute statement: %s", mysql_stmt_error(stmt));
        } else {
            MYSQL_RES* query_result = mysql_stmt_result_metadata(stmt);
            if (!query_result) {
                m_log.warn("No result metadata found");
            } else {
                MYSQL_FIELD* result_fields = mysql_fetch_fields(query_result);
                uint32_t num_result_fields = mysql_num_fields(query_result);

                MYSQL_BIND* bind_results = new MYSQL_BIND[num_result_fields];
                char** result_buffer = new char*[num_result_fields];
                unsigned long* bind_result_length = new unsigned long[num_result_fields];
                my_bool* bind_result_is_null = new my_bool[num_result_fields];
                my_bool* bind_result_error = new my_bool[num_result_fields];

                for (uint32_t i = 0; i < num_result_fields; i++) {
                    m_log.info("Field %d = %s", i, result_fields[i].name);
                    m_log.info("max length = %lu", result_fields[i].length);
                    result_buffer[i] = new char[result_fields[i].length];

                    bind_results[i].buffer_type = MYSQL_TYPE_STRING;
                    bind_results[i].buffer = result_buffer[i];
                    bind_results[i].buffer_length = result_fields[i].length;
                    bind_results[i].is_null = &bind_result_is_null[i];
                    bind_results[i].length = &bind_result_length[i];
                    bind_results[i].error = &bind_result_error[i];
                }

                if (mysql_stmt_bind_result(stmt, bind_results) != 0) {
                    m_log.warn("Failed to bind results: %s", mysql_stmt_error(stmt));
                } else {
                    if (mysql_stmt_store_result(stmt) != 0) {
                        m_log.warn("Failed to store results: %s", mysql_stmt_error(stmt));
                    } else {
                        while (mysql_stmt_fetch(stmt) == 0) {
                            m_log.info("========");
                            for (uint32_t i = 0; i < num_result_fields; i++) {
                                std::string column_name(result_fields[i].name);
                                std::string column_value(result_buffer[i]);

                                m_log.info("%s => %s", column_name.c_str(), column_value.c_str());

                                auto attr_and_cols = m_columns.find(column_name);
                                if (attr_and_cols != m_columns.end()) {
                                    for (auto dest_attr_name : attr_and_cols->second) {
                                        std::vector<std::string> attr_ids(1, dest_attr_name);
                                        std::auto_ptr<shibsp::SimpleAttribute> dest_attr(new shibsp::SimpleAttribute(attr_ids));
                                        dest_attr->getValues().push_back(column_value);
                                        if (dest_attr.get() && dest_attr->valueCount()) {
                                            ctx.getResolvedAttributes().push_back(dest_attr.get());
                                            dest_attr.release();
                                        }
                                    }

                                }
                            }
                        }
                    }
                }

                delete[] bind_result_length;
                delete[] bind_result_is_null;
                delete[] bind_result_error;
                for (uint32_t i = 0; i < num_result_fields; i++) {
                    delete[] result_buffer[i];
                }
                delete[] result_buffer;
                delete[] bind_results;

                mysql_free_result(query_result);
            }
        }
    }

    delete[] bind_params_length;
    delete[] bind_params_is_null;
    delete[] bind_params_error;
    delete[] bind_params;

    mysql_stmt_free_result(stmt);
    mysql_stmt_close(stmt);
    mysql_close(db_connection);

}

void shibsp::MysqlAttributeResolver::getAttributeIds(std::vector<std::string>& attributes) const
{
    for (auto attr_name : m_attributes) {
        attributes.push_back(attr_name);
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
