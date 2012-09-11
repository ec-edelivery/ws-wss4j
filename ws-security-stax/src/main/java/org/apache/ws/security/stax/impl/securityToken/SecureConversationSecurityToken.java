/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ws.security.stax.impl.securityToken;

import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecureConversationSecurityToken extends AbstractInboundSecurityToken {

    //todo implement

    public SecureConversationSecurityToken(WSSecurityContext wsSecurityContext,
                                           CallbackHandler callbackHandler, String id,
                                           WSSConstants.KeyIdentifierType keyIdentifierType) {
        super(wsSecurityContext, callbackHandler, id, keyIdentifierType);
    }

    @Override
    public XMLSecurityConstants.TokenType getTokenType() {
        return WSSConstants.SecureConversationToken;
    }
}
