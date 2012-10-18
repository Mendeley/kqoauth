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
#ifndef KQOAUTHMANAGER_P_H
#define KQOAUTHMANAGER_P_H

#include "kqoauthrequest.h"

class KQOAUTH_EXPORT KQOAuthManagerPrivate {

public:
    KQOAuthManagerPrivate(KQOAuthManager *parent);
    ~KQOAuthManagerPrivate();

    QList< QPair<QString, QString> > createQueryParams(const KQOAuthParameters &requestParams);

    KQOAuthManager::KQOAuthError error;
    KQOAuthManager * const q_ptr;

    QNetworkAccessManager *networkManager;
    bool managerUserSet;
    Q_DECLARE_PUBLIC(KQOAuthManager);
};

#endif // KQOAUTHMANAGER_P_H
