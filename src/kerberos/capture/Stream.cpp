#include "capture/Stream.h"
/* How many bytes it will take to store LEN bytes in base64.  */
#define BASE64_LENGTH(len) (4 * (((len) + 2) / 3))

namespace kerberos
{
    static const char *request_auth_response_template=
            "HTTP/1.0 401 Authorization Required\r\n"
                    "WWW-Authenticate: Basic realm=\"Motion Security Access\"\r\n";

    bool Stream::release()
    {
        for(int i = 0; i < clients.size(); i++)
        {
            shutdown(clients[i], 2);
            FD_CLR(clients[i],&master);
        }

        clients.clear();

        if (sock != INVALID_SOCKET)
        {
            shutdown(sock, 2);
        }
        sock = (INVALID_SOCKET);

        return false;
    }

    bool Stream::open(int port)
    {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        SOCKADDR_IN address;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);

        while(bind(sock, (SOCKADDR*) &address, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
        {
            LERROR << "Stream: couldn't bind sock";
            release();
            usleep(1000*10000);
            sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }

        while(listen(sock, 2) == SOCKET_ERROR)
        {
            LERROR << "Stream: couldn't listen on sock";
            usleep(1000*10000);
        }

        FD_SET(sock, &master);

        return true;
    }

    bool Stream::isOpened()
    {
        return sock != INVALID_SOCKET;
    }

    bool Stream::connect()
    {
        fd_set rread = master;
        struct timeval to = {0,timeout};
        SOCKET maxfd = sock+1;

        if(select( maxfd, &rread, NULL, NULL, &to ) <= 0)
            return true;

        int addrlen = sizeof(SOCKADDR);
        SOCKADDR_IN address = {0};
        SOCKET client = accept(sock, (SOCKADDR*)&address, (socklen_t*) &addrlen);

        if (client == SOCKET_ERROR)
        {
            LERROR << "Stream: couldn't accept connection on sock";
            LINFO << "Stream: reopening master sock";
            release();
            open(port);
            return false;
        }
        const char* control_authentication = (this->user+ ":" + this->password).c_str();

        // lets try to authenticate
        char *userpass = NULL;
        size_t auth_size = strlen(control_authentication);

        char* authentication = (char *) malloc(BASE64_LENGTH(auth_size) + 1);
        userpass = (char *) malloc(auth_size + 4);
        /* base64_encode can read 3 bytes after the end of the string, initialize it */
        memset(userpass, 0, auth_size + 4);
        strcpy(userpass, control_authentication);
        base64_encode(userpass, authentication, auth_size);
        free(userpass);

        char method[10]={'\0'};
        char url[512]={'\0'};
        char protocol[10]={'\0'};

        unsigned short int length = 1023;
        char buffer[1024] = {'\0'};
        int nread = read (client, buffer, length);
        int warningkill = sscanf (buffer, "%9s %511s %9s", method, url, protocol);

        LERROR << "Stream: done processing auth token";

        printf("Authentication-found: %s %s %s", authentication, method, url);
        char * auth = NULL;

        if  (authentication != NULL)
        {
            if ((auth = strstr(buffer,"Basic")) ) {
                char * end_auth = NULL;
                auth = auth + 6;
                if ((end_auth = strstr(auth, "\r\n"))){
                    auth[end_auth - auth] = 0;
                } else {
                    LERROR << "Auth token not found";
                    char response[1024];
                    snprintf (response, sizeof (response),request_auth_response_template, method);
                    _write( client, response, strlen (response));
                    return false;
                }

                if (strcmp(auth, authentication)) {
                    LERROR << "Wrong username/password";
                    return false;
                }
            } else {
                LERROR << "Missing auth token";
                // Request Authorization
                char response[1024]={'\0'};
                snprintf (response, sizeof (response),request_auth_response_template, method);
                _write (client, response, strlen (response));
                return false;
            }

        } else {
            LINFO << "Authentication set and valid";
        }

        maxfd=(maxfd>client?maxfd:client);
        FD_SET( client, &master );
        _write( client,"HTTP/1.0 200 OK\r\n"
                "Server: Mozarella/2.2\r\n"
                "Accept-Range: bytes\r\n"
                "Max-Age: 0\r\n"
                "Expires: 0\r\n"
                "Cache-Control: no-cache, private\r\n"
                "Pragma: no-cache\r\n"
                "Content-Type: multipart/x-mixed-replace; boundary=mjpegstream\r\n"
                "\r\n",0);

        clients.push_back(client);
        packetsSend[client] = 0;

        return true;
    }

    void Stream::write(Image image)
    {
        try
        {
            // Check if some clients connected
            // if not drop this shit..
            if(clients.size()==0) return;

            // Encode the image
            cv::Mat frame = image.getImage();
            if(frame.cols > 0 && frame.rows > 0)
            {
                std::vector<uchar>outbuf;
                std::vector<int> params;
                params.push_back(cv::IMWRITE_JPEG_QUALITY);
                params.push_back(quality);
                cv::imencode(".jpg", frame, outbuf, params);
                int outlen = outbuf.size();

                for(int i = 0; i < clients.size(); i++)
                {
                    packetsSend[clients[i]]++;

                    int error = 0;
                    socklen_t len = sizeof (error);
                    int retval = getsockopt(clients[i], SOL_SOCKET, SO_ERROR, &error, &len);

                    if (retval == 0 && error == 0)
                    {
                        char head[400];
                        sprintf(head,"--mjpegstream\r\nContent-Type: image/jpeg\r\nContent-Length: %lu\r\n\r\n",outlen);

                        _write(clients[i],head,0);

                        retval = getsockopt(clients[i], SOL_SOCKET, SO_ERROR, &error, &len);

                        if (retval == 0 && error == 0)
                        {
                            _write(clients[i],(char*)(&outbuf[0]),outlen);
                        }
                    }

                    if (retval != 0 || error != 0)
                    {
                        shutdown(clients[i], 2);
                        FD_CLR(clients[i],&master);
                        std::vector<int>::iterator position = std::find(clients.begin(), clients.end(), clients[i]);
                        if (position != clients.end())
                        {
                            clients.erase(position);
                        }
                    }
                }
            }
        }
        catch(cv::Exception & ex){}
    }

    void Stream::base64_encode(const char *s, char *store, int length)
    {
        /* Conversion table.  */
        static const char tbl[64] = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '+', '/'
        };

        int i;
        unsigned char *p = (unsigned char *)store;

        /* Transform the 3x8 bits to 4x6 bits, as required by base64.  */
        for (i = 0; i < length; i += 3) {
            *p++ = tbl[s[0] >> 2];
            *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
            *p++ = tbl[((s[1] & 0xf) << 2) + (s[2] >> 6)];
            *p++ = tbl[s[2] & 0x3f];
            s += 3;
        }

        /* Pad the result if necessary...  */
        if (i == length + 1)
            *(p - 1) = '=';
        else if (i == length + 2)
            *(p - 1) = *(p - 2) = '=';

        /* ...and zero-terminate it.  */
        *p = '\0';
    }

}
