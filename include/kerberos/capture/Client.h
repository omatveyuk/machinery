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
    public:

        Client(SOCKET socket) { m_socket = socket;}
        SOCKET & getSocket() {return m_socket;};
    };
}
#endif //KERBEROS_CLIENT_H
