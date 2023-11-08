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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;

import org.apache.jcp.xml.dsig.internal.SignerOutputStream;
import org.apache.jcp.xml.dsig.internal.dom.DOMUtils;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;

/**
 * DOM-based abstract implementation of SignatureMethod.
 *
 */
public abstract class DOMSignatureMethod extends AbstractDOMSignatureMethod {

    private static final String DOM_SIGNATURE_PROVIDER = "org.jcp.xml.dsig.internal.dom.SignatureProvider";

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(DOMSignatureMethod.class);

    private SignatureMethodParameterSpec params;
    private Signature signature;

    /**
     * Creates a <code>DOMSignatureMethod</code>.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this signature method
     */
    DOMSignatureMethod(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params != null &&
            !(params instanceof SignatureMethodParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                ("params must be of type SignatureMethodParameterSpec");
        }
        checkParams((SignatureMethodParameterSpec)params);
        this.params = (SignatureMethodParameterSpec)params;
    }

    /**
     * Creates a <code>DOMSignatureMethod</code> from an element. This ctor
     * invokes the {@link #unmarshalParams unmarshalParams} method to
     * unmarshal any algorithm-specific input parameters.
     *
     * @param smElem a SignatureMethod element
     */
    DOMSignatureMethod(Element smElem) throws MarshalException {
        Element paramsElem = DOMUtils.getFirstChildElement(smElem);
        if (paramsElem != null) {
            params = unmarshalParams(paramsElem);
        }
        try {
            checkParams(params);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new MarshalException(iape);
        }
    }

    /**
     * Returns the signature bytes with any additional formatting
     * necessary for the signature algorithm used. For RSA signatures,
     * no changes are required, and this method should simply return
     * back {@code sig}. For DSA and ECDSA, this method should return the
     * signature in the IEEE P1363 format, the concatenation of r and s.
     *
     * @param key the key used to sign
     * @param sig the signature returned by {@code Signature.sign()}
     * @return the formatted signature
     * @throws IOException
     */
    abstract byte[] postSignFormat(Key key, byte[] sig) throws IOException;

    /**
     * Returns the signature bytes with any conversions that are necessary
     * before the signature can be verified. For RSA signatures,
     * no changes are required, and this method should simply
     * return back {@code sig}. For DSA and ECDSA, this method should
     * return the signature in the DER-encoded ASN.1 format.
     *
     * @param key the key used to sign
     * @param sig the signature
     * @return the formatted signature
     * @throws IOException
     */
    abstract byte[] preVerifyFormat(Key key, byte[] sig) throws IOException;

    static SignatureMethod unmarshal(Element smElem) throws MarshalException {
        String alg = DOMUtils.getAttributeValue(smElem, "Algorithm");
        if (alg.equals(SignatureMethod.RSA_SHA1)) {
            return new SHA1withRSA(smElem);
        } else if (alg.equals(Constants.MoreAlgorithmsSpecNS + "rsa-sha256")) {
            return new SHA256withRSA(smElem);
        } else if (alg.equals(Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311")) {
            return new EcGost34310_2004(smElem);
        } else if (alg.equals("urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512")) {
            return new EcGost3410_2015_512(smElem);
        } else {
            throw new MarshalException
                ("unsupported SignatureMethod algorithm: " + alg);
        }
    }

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    /**
     * Returns an instance of Signature from the specified Provider.
     * The algorithm is specified by the {@code getJCAAlgorithm()} method.
     *
     * @param p the Provider to use
     * @return an instance of Signature implementing the algorithm
     *    specified by {@code getJCAAlgorithm()}
     * @throws NoSuchAlgorithmException if the Provider does not support the
     *    signature algorithm
     */
    Signature getSignature(Provider p)
            throws NoSuchAlgorithmException {
        return (p == null)
            ? Signature.getInstance(getJCAAlgorithm())
            : Signature.getInstance(getJCAAlgorithm(), p);
    }

    @Override
    boolean verify(Key key, SignedInfo si, byte[] sig,
                   XMLValidateContext context)
        throws InvalidKeyException, SignatureException, XMLSignatureException
    {
        if (key == null || si == null || sig == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PublicKey)) {
            throw new InvalidKeyException("key must be PublicKey");
        }
        if (signature == null) {
            Provider p = (Provider)context.getProperty(DOM_SIGNATURE_PROVIDER);
            try {
                signature = getSignature(p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initVerify((PublicKey)key);
        LOG.debug("Signature provider: {}", signature.getProvider());
        LOG.debug("Verifying with key: {}", key);
        LOG.debug("JCA Algorithm: {}", getJCAAlgorithm());
        LOG.debug("Signature Bytes length: {}", sig.length);

        byte[] s;
        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);
            // Do any necessary format conversions
            s = preVerifyFormat(key, sig);
        } catch (IOException ioe) {
            throw new XMLSignatureException(ioe);
        }
        return signature.verify(s);
    }

    @Override
    byte[] sign(Key key, SignedInfo si, XMLSignContext context)
        throws InvalidKeyException, XMLSignatureException
    {
        if (key == null || si == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("key must be PrivateKey");
        }
        if (signature == null) {
            Provider p = (Provider)context.getProperty(DOM_SIGNATURE_PROVIDER);
            try {
                signature = getSignature(p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initSign((PrivateKey)key);
        LOG.debug("Signature provider: {}", signature.getProvider());
        LOG.debug("JCA Algorithm: {}", getJCAAlgorithm());

        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);
            // Return signature with any necessary format conversions
            return postSignFormat(key, signature.sign());
        } catch (SignatureException | IOException ex){
            throw new XMLSignatureException(ex);
        }
    }

    abstract static class AbstractRSASignatureMethod
            extends DOMSignatureMethod {

        AbstractRSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractRSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for RSA.
         */
        @Override
        byte[] postSignFormat(Key key, byte[] sig) {
            return sig;
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for RSA.
         */
        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) {
            return sig;
        }

        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }



    static final class SHA1withRSA extends AbstractRSASignatureMethod {
        SHA1withRSA(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SignatureMethod.RSA_SHA1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA1withRSA";
        }
    }

    static final class SHA256withRSA extends AbstractRSASignatureMethod {
        SHA256withRSA(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA256withRSA";
        }
    }
    
    abstract static class AbstractEcGostSignatureMethod extends DOMSignatureMethod {
        
        AbstractEcGostSignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        
        AbstractEcGostSignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        
        @Override
        byte[] postSignFormat(Key key, byte[] sig) {
            return sig;
        }
        
        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) {
            return sig;
        }
        
        @Override
        Type getAlgorithmType() {
            return Type.ECGOST;
        }
    }
    
    static final class EcGost34310_2004 extends AbstractEcGostSignatureMethod {
        EcGost34310_2004(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        EcGost34310_2004(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
        }
        @Override
        String getJCAAlgorithm() {
            return "ECGOST34310";
        }
    }
    
    static final class EcGost3410_2015_512 extends AbstractEcGostSignatureMethod {
        EcGost3410_2015_512(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
            super(params);
        }
        EcGost3410_2015_512(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
        }
        @Override
        String getJCAAlgorithm() {
            return "ECGOST3410-2015-512";
        }
    }

}
