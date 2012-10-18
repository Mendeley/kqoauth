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
#include <QByteArray>
#include <QDateTime>
#include <QCryptographicHash>
#include <QPair>
#include <QStringList>
#include <QDebug>

#include "kqoauthrequest.h"
#include "kqoauthrequest_p.h"
#include "kqoauthutils.h"
#include "kqoauthglobals.h"

//////////// Private d_ptr implementation /////////

KQOAuthRequestPrivate::KQOAuthRequestPrivate() :
    timeout(0)
{

}

KQOAuthRequestPrivate::~KQOAuthRequestPrivate()
{

}

// This method will not include the "oauthSignature" paramater, since it is calculated from these parameters.
void KQOAuthRequestPrivate::prepareRequest() {

    // If parameter list is not empty, we don't want to insert these values by
    // accident a second time. So giving up.
    if( !requestParameters.isEmpty() ) {
        return;
    }

	requestParameters.append( qMakePair( OAUTH_KEY_SIGNATURE_METHOD, QString("HMAC-SHA1") ));
        requestParameters.append( qMakePair( OAUTH_KEY_CONSUMER_KEY, oauthConsumerKey ));
        requestParameters.append( qMakePair( OAUTH_KEY_VERSION, QString("1.0") ));
        requestParameters.append( qMakePair( OAUTH_KEY_TIMESTAMP, this->oauthTimestamp() ));
        requestParameters.append( qMakePair( OAUTH_KEY_NONCE, this->oauthNonce() ));
        requestParameters.append( qMakePair( OAUTH_KEY_TOKEN, oauthToken ));
}

void KQOAuthRequestPrivate::signRequest() {

    const QByteArray baseString = this->requestBaseString();
	
	
    QString signature = KQOAuthUtils::oauthSignature(baseString, oauthConsumerSecretKey, oauthTokenSecret);
    requestParameters.append( qMakePair( OAUTH_KEY_SIGNATURE, signature) );
}

QByteArray KQOAuthRequestPrivate::requestBaseString() {
    QByteArray baseString;

    // Every request has these as the common parameters.
    baseString.append( oauthHttpMethodString.toUtf8() + "&");                                                     // HTTP method
    baseString.append( QUrl::toPercentEncoding( oauthRequestEndpoint.toString(QUrl::RemoveQuery) ) + "&" ); // The path and query components

    QList< QPair<QString, QString> > baseStringParameters;
    baseStringParameters.append(requestParameters);
    baseStringParameters.append(additionalParameters);

	KQOAuthUtils::sortRequestParameters(baseStringParameters);

    // Last append the request parameters correctly encoded.
    baseString.append(KQOAuthUtils::encodeParameters(baseStringParameters) );
    return baseString;
}

QString KQOAuthRequestPrivate::oauthTimestamp() const {
#if QT_VERSION >= 0x040700
    return QString::number(QDateTime::currentDateTimeUtc().toTime_t());
#else
   return QString::number(QDateTime::currentDateTime().toUTC().toTime_t());
#endif
}

QString KQOAuthRequestPrivate::oauthNonce() const {
	static int offset = 0;
	QString nonce = QString::number(qrand()+offset);
	++offset;
    return nonce;
}

bool KQOAuthRequestPrivate::validateRequest() const {
        if (oauthRequestEndpoint.isEmpty()
            || oauthConsumerKey.isEmpty()
            || oauthNonce_.isEmpty()
            || oauthTimestamp_.isEmpty()
            || oauthToken.isEmpty()
            || oauthTokenSecret.isEmpty())
			{
				return false;
			}
		 return true;
 }


 KQOAuthRequest::KQOAuthRequest(QObject *parent) :
	 QObject(parent),
	 d_ptr(new KQOAuthRequestPrivate)
 {
	 qsrand(QTime::currentTime().msec());  // We need to seed the nonce random number with something.
										   // However, we cannot do this while generating the nonce since
										   // we might get the same seed. So initializing here should be fine.
 }

 KQOAuthRequest::~KQOAuthRequest()
 {
	 delete d_ptr;
 }

 void KQOAuthRequest::initRequest(const QUrl &requestEndpoint) {
	 Q_D(KQOAuthRequest);

	 if (!requestEndpoint.isValid()) {
		 qWarning() << "Endpoint URL is not valid. Ignoring. This request might not work.";
		 return;
	 }

	 // Clear the request
	 clearRequest();

	 // Set smart defaults.
	 d->oauthRequestEndpoint = requestEndpoint;
	 d->oauthTimestamp_ = d->oauthTimestamp();
	 d->oauthNonce_ = d->oauthNonce();
	 this->setHttpMethod(KQOAuthRequest::POST);
	 d->contentType = "application/x-www-form-urlencoded";
 }

 void KQOAuthRequest::setConsumerKey(const QString &consumerKey) {
	 Q_D(KQOAuthRequest);
	 d->oauthConsumerKey = consumerKey;
 }

 void KQOAuthRequest::setConsumerSecretKey(const QString &consumerSecretKey) {
	 Q_D(KQOAuthRequest);
	 d->oauthConsumerSecretKey = consumerSecretKey;
 }

 void KQOAuthRequest::setTokenSecret(const QString &tokenSecret) {
	 Q_D(KQOAuthRequest);

	 d->oauthTokenSecret = tokenSecret;
 }

 void KQOAuthRequest::setToken(const QString &token) {
	 Q_D(KQOAuthRequest);

	 d->oauthToken = token;
 }

 void KQOAuthRequest::setVerifier(const QString &verifier) {
	 Q_D(KQOAuthRequest);

	 d->oauthVerifier = verifier;
 }

 void KQOAuthRequest::setHttpMethod(KQOAuthRequest::RequestHttpMethod httpMethod) {
	 Q_D(KQOAuthRequest);

	 QString requestHttpMethodString;

	 switch (httpMethod) {
	 case KQOAuthRequest::GET:
		 requestHttpMethodString = "GET";
		 break;
	 case KQOAuthRequest::POST:
		 requestHttpMethodString = "POST";
		 break;
	 }

	 d->oauthHttpMethod = httpMethod;
	 d->oauthHttpMethodString = requestHttpMethodString;
 }

 KQOAuthRequest::RequestHttpMethod KQOAuthRequest::httpMethod() const {
	 Q_D(const KQOAuthRequest);

	 return d->oauthHttpMethod;
 }

 void KQOAuthRequest::setAdditionalParameters(const KQOAuthParameters &additionalParams) {
	 Q_D(KQOAuthRequest);

	 QList<QString> additionalKeys = additionalParams.keys();
	 QList<QString> additionalValues = additionalParams.values();

	 int i=0;
	 foreach(QString key, additionalKeys) {
		 QString value = additionalValues.at(i);
		 d->additionalParameters.append( qMakePair(key, value) );
		 i++;
	 }
 }

 KQOAuthParameters KQOAuthRequest::additionalParameters() const {
	 Q_D(const KQOAuthRequest);

	 QMultiMap<QString, QString> additionalParams;
	 for(int i=0; i<d->additionalParameters.size(); i++) {
		 additionalParams.insert(d->additionalParameters.at(i).first,
								 d->additionalParameters.at(i).second);
	 }

	 return additionalParams;
 }

 QUrl KQOAuthRequest::requestEndpoint() const {
	 Q_D(const KQOAuthRequest);
	 return d->oauthRequestEndpoint;
 }

 void KQOAuthRequest::setRequestEndpoint(const QUrl& url) {
	 Q_D(KQOAuthRequest);
	 d->oauthRequestEndpoint = url;
 }

 QList<QByteArray> KQOAuthRequest::requestParameters() {
	 Q_D(KQOAuthRequest);

	 QList<QByteArray> requestParamList;

	 d->prepareRequest();
	 if (!isValid() ) {
		 qWarning() << "Invalid request";
		 Q_ASSERT(false);
	 }

	 d->signRequest();

	 QPair<QString, QString> requestParam;
	 QString param;
	 QString value;
	 foreach (requestParam, d->requestParameters) {
		 param = requestParam.first;
		 value = requestParam.second;
		 if (param != OAUTH_KEY_SIGNATURE) {
			 value = QUrl::toPercentEncoding(value);
		 }

		 requestParamList.append(QString(param + "=\"" + value +"\"").toUtf8());
	 }

	 return requestParamList;
 }

 QString KQOAuthRequest::contentType()
 {
	 Q_D(const KQOAuthRequest);
	 return d->contentType;
 }

 void KQOAuthRequest::setContentType(const QString &contentType)
 {
	 Q_D(KQOAuthRequest);
	 d->contentType = contentType;
 }

 QByteArray KQOAuthRequest::rawData()
 {
	 Q_D(const KQOAuthRequest);
	 return d->postRawData;
 }

 void KQOAuthRequest::setRawData(const QByteArray &rawData)
 {
	 Q_D(KQOAuthRequest);
	 d->postRawData = rawData;
 }

 QByteArray KQOAuthRequest::requestBody() const {
	 Q_D(const KQOAuthRequest);

	 QByteArray postBodyContent;
	 bool first = true;
	 for(int i=0; i < d->additionalParameters.size(); i++) {
		 if(!first) {
			 postBodyContent.append("&");
		 } else {
			 first = false;
		 }

		 QString key = d->additionalParameters.at(i).first;
		 QString value = d->additionalParameters.at(i).second;

		 postBodyContent.append(QUrl::toPercentEncoding(key) + QString("=").toUtf8() +
								QUrl::toPercentEncoding(value));
	 }
	 return postBodyContent;
 }

 bool KQOAuthRequest::isValid() const {
	 Q_D(const KQOAuthRequest);

	 return d->validateRequest();
 }

 void KQOAuthRequest::setTimeout(int timeoutMilliseconds) {
	 Q_D(KQOAuthRequest);
	 d->timeout = timeoutMilliseconds;
 }

 void KQOAuthRequest::clearRequest() {
	 Q_D(KQOAuthRequest);

	 d->oauthConsumerKey = "";
	 d->oauthConsumerSecretKey = "";
	 d->oauthToken = "";
	 d->oauthTokenSecret = "";
	 resetRequest();
 }

 void KQOAuthRequest::resetRequest() {
	 Q_D(KQOAuthRequest);

	 d->oauthRequestEndpoint = "";
	 d->oauthHttpMethodString = "";
	 d->oauthVerifier = "";
	 d->oauthTimestamp_ = d_ptr->oauthTimestamp();
	 d->oauthNonce_ = d_ptr->oauthNonce();
	 d->requestParameters.clear();
	 d->additionalParameters.clear();
	 d->timeout = 0;
 }

void KQOAuthRequest::requestTimerStart()
{
    Q_D(KQOAuthRequest);
    if (d->timeout > 0) {
        connect(&(d->timer), SIGNAL(timeout()), this, SIGNAL(requestTimedout()));
        d->timer.start(d->timeout);
    }
}

void KQOAuthRequest::requestTimerStop()
{
    Q_D(KQOAuthRequest);
    if (d->timeout > 0) {
        disconnect(&(d->timer), SIGNAL(timeout()), this, SIGNAL(requestTimedout()));
        d->timer.stop();
    }
}
