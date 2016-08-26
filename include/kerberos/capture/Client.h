//
// Created by parallels on 8/23/16.
//

#ifndef KERBEROS_CLIENT_H
#define KERBEROS_CLIENT_H
#define SOCKET    int

namespace kerberos {
    class Client {
    private:
        SOCKET m_socket;

    public:

        Client(SOCKET socket);
        SOCKET getSocket() const;
        friend bool operator==(const Client& x, const Client& y);
        friend bool operator!=(const Client& x, const Client& y);
    };
}
#endif //KERBEROS_CLIENT_H
