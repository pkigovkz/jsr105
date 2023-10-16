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
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalizationMethod;
import org.apache.jcp.xml.dsig.internal.dom.DOMManifest;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperties;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperty;
import org.apache.jcp.xml.dsig.internal.dom.DOMTransform;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * DOM-based implementation of XMLSignatureFactory.
 *
 */
public final class DOMXMLSignatureFactory extends XMLSignatureFactory {

    /**
     * Initializes a new instance of this class.
     */
    public DOMXMLSignatureFactory() {}

    @Override
    public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki) {
        return new DOMXMLSignature(si, ki, null, null, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki,
        List objects, String id, String signatureValueId) {
        return new DOMXMLSignature(si, ki, objects, id, signatureValueId);
    }

    @Override
    public Reference newReference(String uri, DigestMethod dm) {
        return newReference(uri, dm, null, null, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm, List transforms,
        String type, String id) {
        return new DOMReference(uri, type, dm, transforms, id, getProvider());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm,
        List appliedTransforms, Data result, List transforms, String type,
        String id) {
        if (appliedTransforms == null) {
            throw new NullPointerException("appliedTransforms cannot be null");
        }
        if (appliedTransforms.isEmpty()) {
            throw new NullPointerException("appliedTransforms cannot be empty");
        }
        if (result == null) {
            throw new NullPointerException("result cannot be null");
        }
        return new DOMReference
            (uri, type, dm, appliedTransforms, result, transforms, id, getProvider());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm, List transforms,
        String type, String id, byte[] digestValue) {
        if (digestValue == null) {
            throw new NullPointerException("digestValue cannot be null");
        }
        return new DOMReference
            (uri, type, dm, null, null, transforms, id, digestValue, getProvider());
    }

    @Override
    @SuppressWarnings({ "rawtypes" })
    public SignedInfo newSignedInfo(CanonicalizationMethod cm,
        SignatureMethod sm, List references) {
        return newSignedInfo(cm, sm, references, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignedInfo newSignedInfo(CanonicalizationMethod cm,
        SignatureMethod sm, List references, String id) {
        return new DOMSignedInfo(cm, sm, references, id);
    }

    // Object factory methods
    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public XMLObject newXMLObject(List content, String id, String mimeType,
        String encoding) {
        return new DOMXMLObject(content, id, mimeType, encoding);
    }

    @Override
    @SuppressWarnings({ "rawtypes" })
    public Manifest newManifest(List references) {
        return newManifest(references, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Manifest newManifest(List references, String id) {
        return new DOMManifest(references, id);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignatureProperties newSignatureProperties(List props, String id) {
        return new DOMSignatureProperties(props, id);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignatureProperty newSignatureProperty
        (List info, String target, String id) {
        return new DOMSignatureProperty(info, target, id);
    }

    @Override
    public XMLSignature unmarshalXMLSignature(XMLValidateContext context)
        throws MarshalException {

        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }
        return unmarshal(((DOMValidateContext) context).getNode(), context);
    }

    @Override
    public XMLSignature unmarshalXMLSignature(XMLStructure xmlStructure)
        throws MarshalException {

        if (xmlStructure == null) {
            throw new NullPointerException("xmlStructure cannot be null");
        }
        if (!(xmlStructure instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("xmlStructure must be of type DOMStructure");
        }
        return unmarshal
            (((javax.xml.crypto.dom.DOMStructure) xmlStructure).getNode(),
             new UnmarshalContext());
    }

    private static class UnmarshalContext extends DOMCryptoContext {
        UnmarshalContext() {}
    }

    private XMLSignature unmarshal(Node node, XMLCryptoContext context)
        throws MarshalException {

        node.normalize();

        Element element = null;
        if (node.getNodeType() == Node.DOCUMENT_NODE) {
            element = ((Document) node).getDocumentElement();
        } else if (node.getNodeType() == Node.ELEMENT_NODE) {
            element = (Element) node;
        } else {
            throw new MarshalException
                ("Signature element is not a proper Node");
        }

        // check tag
        String tag = element.getLocalName();
        String namespace = element.getNamespaceURI();
        if (tag == null || namespace == null) {
            throw new MarshalException("Document implementation must " +
                "support DOM Level 2 and be namespace aware");
        }
        if ("Signature".equals(tag) && XMLSignature.XMLNS.equals(namespace)) {
            try {
                return new DOMXMLSignature(element, context, getProvider());
            } catch (MarshalException me) {
                throw me;
            } catch (Exception e) {
                throw new MarshalException(e);
            }
        } else {
            throw new MarshalException("Invalid Signature tag: " + namespace + ":" + tag);
        }
    }

    @Override
    public boolean isFeatureSupported(String feature) {
        if (feature == null) {
            throw new NullPointerException();
        } else {
            return false;
        }
    }

    @Override
    public DigestMethod newDigestMethod(String algorithm,
        DigestMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        if (algorithm == null) {
            throw new NullPointerException();
        }
        if (algorithm.equals(DigestMethod.SHA1)) {
            return new DOMDigestMethod.SHA1(params);
        } else if (algorithm.equals(DigestMethod.SHA256)) {
            return new DOMDigestMethod.SHA256(params);
        } else if (algorithm.equals("http://www.w3.org/2001/04/xmldsig-more#gost34311")) {
            return new DOMDigestMethod.Gost34311_95(params);
        } else if (algorithm.equals("urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512")) {
            return new DOMDigestMethod.Gost3411_2015_512(params);
        } else {
            throw new NoSuchAlgorithmException("unsupported algorithm");
        }
    }

    @Override
    public SignatureMethod newSignatureMethod(String algorithm,
        SignatureMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        if (algorithm == null) {
            throw new NullPointerException();
        }
        if (algorithm.equals(SignatureMethod.RSA_SHA1)) {
            return new DOMSignatureMethod.SHA1withRSA(params);
        } else if (algorithm.equals(DOMSignatureMethod.RSA_SHA256)) {
            return new DOMSignatureMethod.SHA256withRSA(params);
        } else if (algorithm.equals("http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311")) {
            return new DOMSignatureMethod.EcGost34310_2004(params);
        } else if (algorithm
                .equals("urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512")) {
            return new DOMSignatureMethod.EcGost3410_2015_512(params);
        } else {
            throw new NoSuchAlgorithmException("unsupported algorithm");
        }
    }

    @Override
    public Transform newTransform(String algorithm,
        TransformParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {

        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        spi.init(params);
        return new DOMTransform(spi);
    }

    @Override
    public Transform newTransform(String algorithm,
        XMLStructure params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        if (params == null) {
            spi.init(null);
        } else {
            spi.init(params, null);
        }
        return new DOMTransform(spi);
    }

    @Override
    public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
        C14NMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        spi.init(params);
        return new DOMCanonicalizationMethod(spi);
    }

    @Override
    public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
        XMLStructure params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }
        if (params == null) {
            spi.init(null);
        } else {
            spi.init(params, null);
        }

        return new DOMCanonicalizationMethod(spi);
    }

    @Override
    public URIDereferencer getURIDereferencer() {
        return DOMURIDereferencer.INSTANCE;
    }
}
