#ifndef DATABASE_H
#define DATABASE_H

#include <pqxx/pqxx>
#include <iostream>
#include <string>
#include <memory>
#include <vector>

namespace postegre {
    class Database {
    public:
        static Database &get_database(const std::string& conn_str = "") {
            static Database instance(conn_str);  // Singleton instance'ı
            return instance;
        }

        template<typename... Args>
        pqxx::result execute_query(const std::string& query, Args... args) {
            if (!connection->is_open()) {
                std::cerr << "Veritabanı bağlantısı başarısız!" << std::endl;
                throw std::runtime_error("Veritabanına bağlanılamadı");
            }

            pqxx::work txn(*connection);
            pqxx::result res;

            try {
                if (sizeof...(args) == 0) {
                    res = txn.exec(query);
                } else {
                    res = txn.exec_params(query, args...);
                }
                txn.commit();
            } catch (const std::exception& e) {
                std::cerr << "Hata: " << e.what() << std::endl;
                txn.abort(); // İşlemi geri al
                throw;
            }

            return res;
        }

    private:
        std::unique_ptr<pqxx::connection> connection;

        Database(const std::string& conn_str)
            : connection(std::make_unique<pqxx::connection>(conn_str.empty() ? "host=localhost dbname=test" : conn_str)) {
            if (connection->is_open()) {
                std::cout << "Veritabanına başarılı şekilde bağlandınız." << std::endl;
            } else {
                std::cerr << "Veritabanı bağlantısı başarısız!" << std::endl;
            }
        }

        Database(const Database&) = delete;
        Database& operator=(const Database&) = delete;
    };
}

#endif // DATABASE_H
