/**
 * KQOAuth - An OAuth authentication library for Qt.
 *
 * Author: Johan Paul (johan.paul@gmail.com)
 *         http://www.johanpaul.com
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  KQOAuth is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with KQOAuth.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef KQOAUTHMANAGER_H
#define KQOAUTHMANAGER_H

#include <QObject>
#include <QMultiMap>
#include <QNetworkReply>

#include "kqoauthrequest.h"

class KQOAuthRequest;
class QNetworkAccessManager;
class QUrl;
class QByteArray;


class KQOAuthManager : public QObject
{
    Q_OBJECT
public:

    enum KQOAuthError {
        NoError,                    // No error
        NetworkError,               // Network error: timeout, cannot connect.
        RequestEndpointError,       // Request endpoint is not valid.
        RequestValidationError,     // Request is not valid: some parameter missing?
        RequestUnauthorized,        // Authorization error: trying to access a resource without tokens.
        RequestError,               // The given request to KQOAuthManager is invalid: NULL?,
        ManagerError                // Manager error, cannot use for sending requests.
    };

    explicit KQOAuthManager(QObject *parent = 0);
    ~KQOAuthManager();

    /**
     * The manager executes the given request. It takes the HTTP parameters from the
     * request and uses QNetworkAccessManager to submit the HTTP request to the net.
     * When the request is done it will emit signal requestReady(QByteArray networkReply).
     * NOTE: At the moment there is no timeout for the request.
     */
    QNetworkReply* executeRequest(KQOAuthRequest *request, const QVariant& userData = QVariant());

    /**
     * Sets a custom QNetworkAccessManager to handle network requests. This method can be useful if the
     * application is using some proxy settings for example.
     * The application is responsible for deleting this manager. KQOAuthManager will not delete any
     * previously given manager.
     * If the manager is NULL, the manager will not be set and the KQOAuthManager::Error.
     * If no manager is given, KQOAuthManager will use the default one it will create by itself.
     */
    void setNetworkManager(QNetworkAccessManager *manager);

private:

	KQOAuthManager::KQOAuthError error;
	QList< QPair<QString, QString> > createQueryParams(const KQOAuthParameters &requestParams);
    QNetworkAccessManager *networkManager;
    bool managerUserSet;
};

#endif // KQOAUTHMANAGER_H
