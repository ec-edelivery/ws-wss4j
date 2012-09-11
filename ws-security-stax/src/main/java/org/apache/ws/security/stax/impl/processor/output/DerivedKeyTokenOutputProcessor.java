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
package org.apache.ws.security.stax.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.apache.ws.security.common.derivedKey.AlgoFactory;
import org.apache.ws.security.common.derivedKey.ConversationException;
import org.apache.ws.security.common.derivedKey.DerivationAlgorithm;
import org.apache.ws.security.common.ext.WSPasswordCallback;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DerivedKeyTokenOutputProcessor extends AbstractOutputProcessor {

    public DerivedKeyTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            final OutboundSecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken();
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }

            final String wsuIdDKT = IDGenerator.generateID(null);

            int offset = 0;
            int length = 0;

            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                length = JCEAlgorithmMapper.getAlgorithmMapping(getSecurityProperties().getSignatureAlgorithm()).getKeyLength() / 8;
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                length = JCEAlgorithmMapper.getAlgorithmMapping(getSecurityProperties().getEncryptionSymAlgorithm()).getKeyLength() / 8;
            }

            byte[] label;
            try {
                label = (WSSConstants.WS_SecureConversation_DEFAULT_LABEL + WSSConstants.WS_SecureConversation_DEFAULT_LABEL).getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new WSSecurityException("UTF-8 encoding is not supported", e);
            }

            byte[] nonce = new byte[16];
            WSSConstants.secureRandom.nextBytes(nonce);

            byte[] seed = new byte[label.length + nonce.length];
            System.arraycopy(label, 0, seed, 0, label.length);
            System.arraycopy(nonce, 0, seed, label.length, nonce.length);

            DerivationAlgorithm derivationAlgorithm;
            try {
                derivationAlgorithm = AlgoFactory.getInstance(WSSConstants.P_SHA_1);
            } catch (ConversationException e) {
                throw new WSSecurityException(e.getMessage(), e);
            }

            final byte[] derivedKeyBytes;
            try {
                byte[] secret;
                if (wrappingSecurityToken.getTokenType() == WSSConstants.SecurityContextToken) {
                    WSPasswordCallback passwordCallback = new WSPasswordCallback(wsuIdDKT, WSPasswordCallback.Usage.SECRET_KEY);
                    WSSUtils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, wsuIdDKT);
                    if (passwordCallback.getKey() == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKey", wsuIdDKT);
                    }
                    secret = passwordCallback.getKey();
                } else {
                    secret = wrappingSecurityToken.getSecretKey("").getEncoded();
                }

                derivedKeyBytes = derivationAlgorithm.createKey(secret, seed, offset, length);
            } catch (ConversationException e) {
                throw new WSSecurityException(e.getMessage(), e);
            }

            final GenericOutboundSecurityToken derivedKeySecurityToken = new GenericOutboundSecurityToken(wsuIdDKT, WSSConstants.DerivedKeyToken) {

                @Override
                public Key getSecretKey(String algorithmURI) throws WSSecurityException {

                    Key key = null;
                    try {
                        key = super.getSecretKey(algorithmURI);
                    } catch (XMLSecurityException e) {
                        throw new WSSecurityException(e.getMessage(), e);
                    }
                    if (key != null) {
                        return key;
                    }
                    String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
                    key = new SecretKeySpec(derivedKeyBytes, algoFamily);
                    setSecretKey(algorithmURI, key);
                    return key;
                }
            };

            derivedKeySecurityToken.setKeyWrappingToken(wrappingSecurityToken);
            wrappingSecurityToken.addWrappedToken(derivedKeySecurityToken);

            SecurityTokenProvider derivedKeysecurityTokenProvider = new SecurityTokenProvider() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return derivedKeySecurityToken;
                }

                @Override
                public String getId() {
                    return wsuIdDKT;
                }
            };

            if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, wsuIdDKT);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, wsuIdDKT);
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, wsuIdDKT);
            }
            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuIdDKT, derivedKeysecurityTokenProvider);
            FinalDerivedKeyTokenOutputProcessor finalDerivedKeyTokenOutputProcessor =
                    new FinalDerivedKeyTokenOutputProcessor(derivedKeySecurityToken, offset, length, new String(Base64.encodeBase64(nonce)));
            finalDerivedKeyTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalDerivedKeyTokenOutputProcessor.setAction(getAction());
            finalDerivedKeyTokenOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
            finalDerivedKeyTokenOutputProcessor.init(outputProcessorChain);
            derivedKeySecurityToken.setProcessor(finalDerivedKeyTokenOutputProcessor);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalDerivedKeyTokenOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;
        private final int offset;
        private final int length;
        private final String nonce;

        FinalDerivedKeyTokenOutputProcessor(OutboundSecurityToken securityToken, int offset, int length, String nonce) throws XMLSecurityException {

            super();
            this.securityToken = securityToken;
            this.offset = offset;
            this.length = length;
            this.nonce = nonce;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, securityToken.getId()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_DerivedKeyToken, true, attributes);

                    createSecurityTokenReferenceStructureForDerivedKey(subOutputProcessorChain, securityToken,
                            ((WSSSecurityProperties) getSecurityProperties()).getDerivedKeyKeyIdentifierType(),
                            ((WSSSecurityProperties) getSecurityProperties()).getDerivedKeyTokenReference(), getSecurityProperties().isUseSingleCert());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Offset, false, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, "" + offset);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Offset);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Length, false, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, "" + length);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Length);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Nonce, false, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, nonce);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Nonce);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_DerivedKeyToken);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }

        protected void createSecurityTokenReferenceStructureForDerivedKey(
                OutputProcessorChain outputProcessorChain,
                OutboundSecurityToken securityToken,
                WSSConstants.KeyIdentifierType keyIdentifierType,
                WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference,
                boolean useSingleCertificate)
                throws XMLStreamException, XMLSecurityException {

            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            } else if (derivedKeyTokenReference == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_WSS_ENC_KEY_VALUE_TYPE));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
            String tokenId = securityToken.getKeyWrappingToken().getId();

            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SKI_KEY_IDENTIFIER) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType);
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, "unsupportedSecurityToken");
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }
}
