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

package org.apache.wss4j.dom.validate;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;

import org.apache.wss4j.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.Token;

/**
 * This class stores various Credential types that can be validated and/or returned by a
 * Validator implementation. It also stores an optional Principal object which can provide
 * context information to the validators.
 */
public class Credential {

    private PublicKey publicKey;
    private X509Certificate[] certs;
    private Token token;
    private SamlAssertionWrapper transformedToken;
    private Principal principal;
    private byte[] secretKey;
    private Subject subject;
    private Object delegationCredential;

    /**
     * Set a token to be validated
     * @param token a token to be validated
     */
    public void setToken(Token token) {
        this.token = token;
    }

    /**
     * Get a token to be validated
     * @return a token to be validated
     */
    public Token getToken() {
        return token;
    }

    /**
     * Set a SecretKey (byte[]) to be validated
     * @param secretKey a SecretKey (byte) to be validated
     */
    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Get a SecretKey (byte[]) to be validated
     * @return a SecretKey (byte[]) to be validated
     */
    public byte[] getSecretKey() {
        return secretKey;
    }


    /**
     * Set a PublicKey to be validated
     * @param publicKey a PublicKey to be validated
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Get a PublicKey to be validated
     * @return a PublicKey to be validated
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Set an X509Certificate chain to be validated
     * @param certs an X509Certificate chain to be validated
     */
    public void setCertificates(X509Certificate[] certs) {
        this.certs = certs;
    }

    /**
     * Get an X509Certificate chain to be validated
     * @return an X509Certificate chain to be validated
     */
    public X509Certificate[] getCertificates() {
        return certs;
    }

    /**
     * Set an SamlAssertionWrapper instance which corresponds to a Transformed Token.
     * @param transformedToken a transformed SamlAssertionWrapper instance
     */
    public void setTransformedToken(SamlAssertionWrapper transformedToken) {
        this.transformedToken = transformedToken;
    }

    /**
     * Get an SamlAssertionWrapper instance which corresponds to a Transformed Token.
     * @return a transformed SamlAssertionWrapper instance
     */
    public SamlAssertionWrapper getTransformedToken() {
        return transformedToken;
    }

    /**
     * Set the principal that supplies context information to the validators.
     * @param principal the principal that supplies context information to the validators
     */
    public void setPrincipal(Principal principal) {
        this.principal = principal;
    }

    /**
     * Get the principal
     * @return the principal
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * Set the subject that may result from the Validation process
     * @param subject the subject that may result from the Validation process
     */
    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    /**
     * Get the subject that may result from the Validation process
     * @return the subject that may result from the Validation process
     */
    public Subject getSubject() {
        return subject;
    }

    public Object getDelegationCredential() {
        return delegationCredential;
    }

    public void setDelegationCredential(Object delegationCredential) {
        this.delegationCredential = delegationCredential;
    }

}
