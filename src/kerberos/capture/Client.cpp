//
// Created by parallels on 8/23/16.
//

#include "capture/Client.h"

namespace kerberos {
    Client::Client(SOCKET socket) { m_socket = socket; }

    SOCKET Client::getSocket() const { return m_socket; };

    bool operator==(const Client& x, const Client& y) {
        return x.getSocket() == y.getSocket();
    }

    bool operator!=(const Client& x, const Client& y) {
        return !(x == y);
    }
}