# KalkancryptXMLDSig
Kalkancrypt JSR-105 provider based on Apache XML Security

### Usage with WSS4J
```
WSProviderConfig.setAddJceProviders(false);
WSProviderConfig.init();
Security.removeProvider("XMLDSig");
WSProviderConfig.addJceProvider("KALKAN", new KalkanProvider());
WSProviderConfig.addJceProvider("KalkancryptXMLDSig", new KalkancryptXMLDSigRI());
KncaXS.loadXMLSecurity();
```
