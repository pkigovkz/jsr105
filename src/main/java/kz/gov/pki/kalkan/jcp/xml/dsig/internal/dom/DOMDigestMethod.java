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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package kz.gov.pki.kalkan.jcp.xml.dsig.internal.dom;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;

import org.apache.jcp.xml.dsig.internal.dom.DOMStructure;
import org.apache.jcp.xml.dsig.internal.dom.DOMUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * DOM-based abstract implementation of DigestMethod.
 *
 */
public abstract class DOMDigestMethod extends DOMStructure
    implements DigestMethod {

    private DigestMethodParameterSpec params;

    /**
     * Creates a <code>DOMDigestMethod</code>.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this digest method
     */
    DOMDigestMethod(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params != null && !(params instanceof DigestMethodParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                ("params must be of type DigestMethodParameterSpec");
        }
        checkParams((DigestMethodParameterSpec)params);
        this.params = (DigestMethodParameterSpec)params;
    }

    /**
     * Creates a <code>DOMDigestMethod</code> from an element. This constructor
     * invokes the abstract {@link #unmarshalParams unmarshalParams} method to
     * unmarshal any algorithm-specific input parameters.
     *
     * @param dmElem a DigestMethod element
     */
    DOMDigestMethod(Element dmElem) throws MarshalException {
        Element paramsElem = DOMUtils.getFirstChildElement(dmElem);
        if (paramsElem != null) {
            params = unmarshalParams(paramsElem);
        }
        try {
            checkParams(params);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new MarshalException(iape);
        }
    }

    static DigestMethod unmarshal(Element dmElem) throws MarshalException {
        String alg = DOMUtils.getAttributeValue(dmElem, "Algorithm");
        if (alg.equals(DigestMethod.SHA1)) {
            return new SHA1(dmElem);
        } else if (alg.equals(DigestMethod.SHA256)) {
            return new SHA256(dmElem);
        } else {
            throw new MarshalException("unsupported DigestMethod algorithm: " +
                                       alg);
        }
    }

    /**
     * Checks if the specified parameters are valid for this algorithm. By
     * default, this method throws an exception if parameters are specified
     * since most DigestMethod algorithms do not have parameters. Subclasses
     * should override it if they have parameters.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this digest method
     */
    void checkParams(DigestMethodParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("no parameters " +
                "should be specified for the " + getMessageDigestAlgorithm() +
                " DigestMethod algorithm");
        }
    }

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    /**
     * Unmarshals <code>DigestMethodParameterSpec</code> from the specified
     * <code>Element</code>.  By default, this method throws an exception since
     * most DigestMethod algorithms do not have parameters. Subclasses should
     * override it if they have parameters.
     *
     * @param paramsElem the <code>Element</code> holding the input params
     * @return the algorithm-specific <code>DigestMethodParameterSpec</code>
     * @throws MarshalException if the parameters cannot be unmarshalled
     */
    DigestMethodParameterSpec unmarshalParams(Element paramsElem)
        throws MarshalException
    {
        throw new MarshalException("no parameters should " +
                                   "be specified for the " +
                                   getMessageDigestAlgorithm() +
                                   " DigestMethod algorithm");
    }

    /**
     * This method invokes the abstract {@link #marshalParams marshalParams}
     * method to marshal any algorithm-specific parameters.
     */
    @Override
    public void marshal(Node parent, String prefix, DOMCryptoContext context)
        throws MarshalException
    {
        Document ownerDoc = DOMUtils.getOwnerDocument(parent);

        Element dmElem = DOMUtils.createElement(ownerDoc, "DigestMethod",
                                                XMLSignature.XMLNS, prefix);
        DOMUtils.setAttribute(dmElem, "Algorithm", getAlgorithm());

        if (params != null) {
            marshalParams(dmElem, prefix);
        }

        parent.appendChild(dmElem);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof DigestMethod)) {
            return false;
        }
        DigestMethod odm = (DigestMethod)o;

        boolean paramsEqual = params == null ? odm.getParameterSpec() == null :
            params.equals(odm.getParameterSpec());

        return getAlgorithm().equals(odm.getAlgorithm()) && paramsEqual;
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (params != null) {
            result = 31 * result + params.hashCode();
        }
        result = 31 * result + getAlgorithm().hashCode();

        return result;
    }

    /**
     * Marshals the algorithm-specific parameters to an Element and
     * appends it to the specified parent element. By default, this method
     * throws an exception since most DigestMethod algorithms do not have
     * parameters. Subclasses should override it if they have parameters.
     *
     * @param parent the parent element to append the parameters to
     * @param prefix the namespace prefix to use
     * @throws MarshalException if the parameters cannot be marshalled
     */
    void marshalParams(Element parent, String prefix)
        throws MarshalException
    {
        throw new MarshalException("no parameters should " +
                                   "be specified for the " +
                                   getMessageDigestAlgorithm() +
                                   " DigestMethod algorithm");
    }

    /**
     * Returns the MessageDigest standard algorithm name.
     */
    abstract String getMessageDigestAlgorithm();

    static final class SHA1 extends DOMDigestMethod {
        SHA1(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.SHA1;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-1";
        }
    }

    static final class SHA256 extends DOMDigestMethod {
        SHA256(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.SHA256;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-256";
        }
    }
    
    static final class Gost34311_95 extends DOMDigestMethod {
        Gost34311_95(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        Gost34311_95(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "GOST34311";
        }
    }
    
    static final class Gost3411_2015_512 extends DOMDigestMethod {
        Gost3411_2015_512(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        Gost3411_2015_512(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "GOST3411-2015-512";
        }
    }

}
