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

using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL MysqlContext : public ResolutionContext
    {
    public:
        MysqlContext(const vector<Attribute*>* attributes) : m_input_attributes(attributes) {
        }

        ~MysqlContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
        }

        const vector<Attribute*>* getInputAttributes() const {
            return m_input_attributes;
        }

        vector<Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }

        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const vector<Attribute*>* m_input_attributes;
        vector<Attribute*> m_attributes;
        static vector<opensaml::Assertion*> m_assertions;   // empty dummy
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
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<Attribute*>* attributes=nullptr
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
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<Attribute*>* attributes=nullptr
            ) const {
            return new MysqlContext(attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new MysqlContext(&session.getAttributes());
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const;

    private:
        vector<map<string, string> > extractQueryParameters(vector<Attribute*> input_attributes) const;
        vector<map<string, string> > runQuery(MYSQL* connection, map<string, string> query_parameters) const;

        xmltooling::logging::Category& m_log;

        string m_connection_host;
        uint32_t m_connection_port;
        string m_connection_username;
        string m_connection_password;
        string m_connection_dbname;

        string m_query;
        vector<string> m_query_param_attr_ids;

        set<string> m_resolve_attr_ids;

        // Maps a column name to a list of IDs of attributes populated by the column
        map<string,vector<string> > m_cols_to_attr_ids;

    };

    AttributeResolver* SHIBSP_DLLLOCAL MysqlAttributeResolverFactory(const xercesc::DOMElement* const & e)
    {
        return new MysqlAttributeResolver(e);
    }

};

vector<opensaml::Assertion*> shibsp::MysqlContext::m_assertions;

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
        string param_attr_id = m_query.substr(match_groups[1].rm_so, match_groups[1].rm_eo);
        m_query_param_attr_ids.push_back(param_attr_id);

        m_query.erase(match_groups[1].rm_so, match_groups[1].rm_eo - match_groups[1].rm_so);
        m_query.replace(match_groups[1].rm_so - 1, 1, "?");

        match_return = regexec(&param_regex, m_query.c_str(), 2, match_groups, 0);
    }

    regfree(&param_regex);

    // Columns
    xercesc::DOMElement* column_element = e ? xmltooling::XMLHelper::getFirstChildElement(e, column) : nullptr;
    while (column_element) {

        string column_name = xmltooling::XMLHelper::getAttrString(column_element, nullptr, name);
        boost::trim(column_name);

        string attr_id = xmltooling::XMLHelper::getAttrString(column_element, nullptr, attribute);
        boost::trim(attr_id);

        if (column_name.empty() || attr_id.empty()) {
            throw ConfigurationException("MySQL AttributeResolver <Column> elements require 'name' and 'attribute' XML attributes.");
        } else {
            auto r = m_resolve_attr_ids.insert(attr_id);
            if (r.second == false) {
                throw ConfigurationException("MySQL AttributeResolver cannot map multiple columns to the same attribute.");
            }

            m_cols_to_attr_ids[column_name].push_back(attr_id);
        }

        column_element = xmltooling::XMLHelper::getNextSiblingElement(column_element, column);
    };

    if (m_cols_to_attr_ids.empty()) {
        throw ConfigurationException("MySQL AttributeResolver requires at least one <Column> element.");
    }

    m_log.info("Query = %s", m_query.c_str());
    for (auto attr_id : m_query_param_attr_ids) {
        m_log.info("Bind attribute: %s", attr_id.c_str());
    }

    m_log.info("Resolves %d attributes", m_resolve_attr_ids.size());
    for (auto attr_id : m_resolve_attr_ids) {
        m_log.info("  %s", attr_id.c_str());
    }

    for (auto col_and_attr_ids : m_cols_to_attr_ids) {
        for (auto attr_id : col_and_attr_ids.second) {
            m_log.info("Column %s -> attribute %s", col_and_attr_ids.first.c_str(), attr_id.c_str());
        }
    }
}

vector<map<string, string> > shibsp::MysqlAttributeResolver::extractQueryParameters(vector<Attribute*> input_attributes) const
{
    vector<map<string, string> > query_params;
    if (!input_attributes.empty()) {

        // All parameter attributes must have the same value count. Query will be run this many times, with the nth
        // query using the nth value of each parameter attribute.
        uint32_t value_count = input_attributes.front()->valueCount();
        query_params.resize(value_count, map<string, string>());

        for (auto attr_id : m_query_param_attr_ids) {
            auto attr = find_if(input_attributes.begin(), input_attributes.end(), [attr_id] (Attribute* a) {
                return attr_id == a->getId();
            });
            if (attr == input_attributes.end()) {
                throw runtime_error("No input attribute for query parameter " + attr_id);
            } else if ((*attr)->valueCount() != value_count) {
                throw runtime_error("All input attributes for query parameters must contain equal number of values.");
            }

            for (uint32_t i = 0; i < value_count; i++) {
                query_params[i][attr_id] = (*attr)->getSerializedValues().at(i);
            }
        }
    }
    return query_params;
}

vector<map<string, string>> shibsp::MysqlAttributeResolver::runQuery(MYSQL* connection, map<string, string> query_params) const
{
    vector<map<string, string> > query_results;

    MYSQL_STMT* stmt = nullptr;
    stmt = mysql_stmt_init(connection);
    if (!stmt) {
        throw runtime_error("Failed to initialize statement: " + string(mysql_stmt_error(stmt)));
    }

    if (mysql_stmt_prepare(stmt, m_query.c_str(), m_query.length()) != 0) {
        mysql_stmt_close(stmt);
        throw runtime_error("Failed to prepare statement: " + string(mysql_stmt_error(stmt)));
    }

    uint32_t num_params = m_query_param_attr_ids.size();

    MYSQL_BIND* bind_params = new MYSQL_BIND[num_params];
    uint64_t* bind_params_length = new uint64_t[num_params];
    my_bool* bind_params_is_null = new my_bool[num_params];
    memset(bind_params_is_null, 0, num_params * sizeof(my_bool));
    my_bool* bind_params_error = new my_bool[num_params];

    for (uint32_t i = 0; i < num_params; i++) {
        bind_params[i].buffer_type = MYSQL_TYPE_STRING;
        auto param_value = query_params.find(m_query_param_attr_ids[i])->second;
        m_log.info("Binding '%s' to %s", param_value.c_str(), m_query_param_attr_ids[i].c_str());
        bind_params[i].buffer = (void *) param_value.c_str();
        bind_params[i].buffer_length = param_value.length();
        bind_params_length[i] = param_value.length();
        bind_params[i].is_null = &bind_params_is_null[i];
        bind_params[i].error = &bind_params_error[i];
        bind_params[i].length = &bind_params_length[i];
    }

    MYSQL_RES* result_set = nullptr;

    if (mysql_stmt_bind_param(stmt, bind_params) != 0) {
        m_log.warn("Failed to bind parameters: %s", mysql_stmt_error(stmt));
    } else if (mysql_stmt_execute(stmt) != 0) {
        m_log.warn("Failed to execute statement: %s", mysql_stmt_error(stmt));
    } else if (!(result_set = mysql_stmt_result_metadata(stmt))) {
        m_log.warn("No result metadata found");
    } else {
        MYSQL_FIELD* result_fields = mysql_fetch_fields(result_set);
        uint32_t num_result_fields = mysql_num_fields(result_set);

        MYSQL_BIND* bind_results = new MYSQL_BIND[num_result_fields];
        uint8_t** result_buffer = new uint8_t*[num_result_fields];
        uint64_t* bind_result_length = new uint64_t[num_result_fields];
        my_bool* bind_result_is_null = new my_bool[num_result_fields];
        my_bool* bind_result_error = new my_bool[num_result_fields];

        for (uint32_t i = 0; i < num_result_fields; i++) {
            m_log.info("Field %d = %s", i, result_fields[i].name);
            result_buffer[i] = new uint8_t[result_fields[i].length];

            bind_results[i].buffer_type = MYSQL_TYPE_STRING;
            bind_results[i].buffer = result_buffer[i];
            bind_results[i].buffer_length = result_fields[i].length;
            bind_results[i].is_null = &bind_result_is_null[i];
            bind_results[i].length = &bind_result_length[i];
            bind_results[i].error = &bind_result_error[i];
        }

        if (mysql_stmt_bind_result(stmt, bind_results) != 0) {
            m_log.warn("Failed to bind results: %s", mysql_stmt_error(stmt));
        } else if (mysql_stmt_store_result(stmt) != 0) {
            m_log.warn("Failed to store results: %s", mysql_stmt_error(stmt));
        } else {
            while (mysql_stmt_fetch(stmt) == 0) {
                map<string, string> row_results;
                m_log.info("=== Row ===");
                for (uint32_t i = 0; i < num_result_fields; i++) {
                    string column_name(result_fields[i].name);
                    if (*bind_results[i].is_null) {
                        m_log.info("Null value in '%s' column.", column_name.c_str());
                    } else {
                        string column_value((char*)result_buffer[i]);
                        m_log.info("%s => %s", column_name.c_str(), column_value.c_str());
                        row_results[column_name] = column_value;
                    }
                }

                query_results.push_back(row_results);
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

        mysql_free_result(result_set);
    }

    delete[] bind_params_length;
    delete[] bind_params_is_null;
    delete[] bind_params_error;
    delete[] bind_params;

    mysql_stmt_free_result(stmt);
    mysql_stmt_close(stmt);

    return query_results;
}

void shibsp::MysqlAttributeResolver::resolveAttributes(shibsp::ResolutionContext& ctx) const
{
    shibsp::MysqlContext& mctx = dynamic_cast<shibsp::MysqlContext&>(ctx);
    if (!mctx.getInputAttributes()) {
        return;
    }

    vector<map<string, string> > all_query_params;
    try {
        all_query_params = extractQueryParameters(*mctx.getInputAttributes());
    } catch (exception& e) {
        m_log.error("Failed to extract query parameters: %s", e.what());
        return;
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

    // Collect attribute values from all row results from all queries.
    map<string, vector<string> > all_attr_values;
    for (auto query_params : all_query_params) {
        try {
            auto query_results = runQuery(db_connection, query_params);
            for (auto row_result : query_results) {
                for (auto col_and_attr_ids : m_cols_to_attr_ids) {
                    auto col_and_row_attr_value = row_result.find(col_and_attr_ids.first);
                    if (col_and_row_attr_value != row_result.end()) {
                        for (auto attr_id : col_and_attr_ids.second) {
                            all_attr_values[attr_id].push_back(col_and_row_attr_value->second);
                        }
                    } else {
                        m_log.warn("Required column '%s' not found in query result.", col_and_attr_ids.first.c_str());
                    }
                }
            }
        } catch (exception& e) {
            m_log.warn("Failed to run query: %s", e.what());
        }
    }

    mysql_close(db_connection);

    // Only add attributes that have values to the resolution context
    for (auto attr_id_and_values : all_attr_values) {

        // Skip attributes for which no values were found.
        if (attr_id_and_values.second.empty()) {
            continue;
        }

        auto attr_id = attr_id_and_values.first;
        auto existing_attr = find_if(mctx.getInputAttributes()->begin(), mctx.getInputAttributes()->end(), [attr_id] (Attribute* a) {
            return attr_id == a->getId();
        });

        // If an attribute with the ID already exists, add values to it. Otherwise, create a new attribute.
        SimpleAttribute* dest_attr = nullptr;
        if (existing_attr != mctx.getInputAttributes()->end()) {
            dest_attr = dynamic_cast<SimpleAttribute*>(*existing_attr);
            if (!dest_attr) {
                m_log.warn("Can't add values to non-simple attribute '%s'", attr_id.c_str());
                continue;
            }
        } else {
            dest_attr = new SimpleAttribute(vector<string>(1, attr_id));
        }

        for (auto val : attr_id_and_values.second) {
            dest_attr->getValues().push_back(val);
        }

        if (existing_attr == mctx.getInputAttributes()->end()) {
            ctx.getResolvedAttributes().push_back(dest_attr);
        }
    }

}

void shibsp::MysqlAttributeResolver::getAttributeIds(vector<string>& attributes) const
{
    for (auto attr_id : m_resolve_attr_ids) {
        attributes.push_back(attr_id);
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
