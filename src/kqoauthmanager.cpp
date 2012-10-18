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
#include <QtCore>
#include <QDesktopServices>

#include "kqoauthmanager.h"

namespace
{
    const QNetworkRequest::Attribute userDataAttribute = static_cast<QNetworkRequest::Attribute>(QNetworkRequest::User + 1);
}

QList< QPair<QString, QString> > KQOAuthManager::createQueryParams(const KQOAuthParameters &requestParams) {
    QList<QString> requestKeys = requestParams.keys();
    QList<QString> requestValues = requestParams.values();

    QList< QPair<QString, QString> > result;
    for(int i=0; i<requestKeys.size(); i++) {
        result.append( qMakePair(requestKeys.at(i),
                                 requestValues.at(i))
                      );
    }

    return result;
}

/////////////// Public implementation ////////////////

KQOAuthManager::KQOAuthManager(QObject *parent) :
    QObject(parent) ,
    error(KQOAuthManager::NoError),
	networkManager(0),
    managerUserSet(false)
{
	setNetworkManager(new QNetworkAccessManager);
}

KQOAuthManager::~KQOAuthManager()
{
    if (!managerUserSet) {
        delete networkManager;
        networkManager = 0;
    }
}

QNetworkReply* KQOAuthManager::executeRequest(KQOAuthRequest *request, const QVariant& userData) {
    if (request == 0) {
        qWarning() << "Request is NULL. Cannot proceed.";
        error = KQOAuthManager::RequestError;
        return 0;
    }

    if (!request->requestEndpoint().isValid()) {
        qWarning() << "Request endpoint URL is not valid. Cannot proceed.";
        error = KQOAuthManager::RequestEndpointError;
        return 0;
    }

    if (!request->isValid()) {
        qWarning() << "Request is not valid. Cannot proceed.";
        error = KQOAuthManager::RequestValidationError;
        return 0;
    }

    QNetworkRequest networkRequest;
    networkRequest.setUrl(request->requestEndpoint());
    networkRequest.setAttribute(userDataAttribute, userData);

    // And now fill the request with "Authorization" header data.
    QList<QByteArray> requestHeaders = request->requestParameters();
    QByteArray authHeader;

    bool first = true;
    foreach (const QByteArray header, requestHeaders) {
        if (!first) {
            authHeader.append(", ");
        } else {
            authHeader.append("OAuth ");
            first = false;
        }

        authHeader.append(header);
    }
    networkRequest.setRawHeader("Authorization", authHeader);

	QNetworkReply* reply = 0;
    if (request->httpMethod() == KQOAuthRequest::GET) 
		{
        // Get the requested additional params as a list of pairs we can give QUrl
        QList< QPair<QString, QString> > urlParams = createQueryParams(request->additionalParameters());

        // Take the original URL and append the query params to it.
        QUrl urlWithParams = networkRequest.url();
        urlWithParams.setQueryItems(urlParams);
        networkRequest.setUrl(urlWithParams);

        // Submit the request including the params.
        reply = networkManager->get(networkRequest);
    } 
	else if (request->httpMethod() == KQOAuthRequest::POST) 
		{

        networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, request->contentType());

        if (request->contentType() == "application/x-www-form-urlencoded") 
			{
				reply = networkManager->post(networkRequest, request->requestBody());
			}
		else 
			{
				reply = networkManager->post(networkRequest, request->rawData());
			}
    }
	return reply;
}

void KQOAuthManager::setNetworkManager(QNetworkAccessManager *manager) {
    if (manager == 0) {
        return;
    }

    if (!managerUserSet && networkManager) {
        delete networkManager;
    }

	managerUserSet = true;
    networkManager = manager;
}
