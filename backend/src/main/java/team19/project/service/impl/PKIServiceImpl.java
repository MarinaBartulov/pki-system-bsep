package team19.project.service.impl;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import team19.project.dto.*;
import team19.project.model.CertificateDB;
import team19.project.model.RevocationReason;
import team19.project.utils.IssuerData;
import team19.project.utils.SubjectData;
import team19.project.repository.StoreCertificates;
import team19.project.service.PKIService;
import team19.project.utils.BigIntGenerator;
import team19.project.utils.CertificateGenerator;
import team19.project.utils.CertificateType;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class PKIServiceImpl implements PKIService {

    @Autowired
    private CertificateGenerator certificateGenerator;
    @Autowired
    private StoreCertificates store;
    @Autowired
    private BigIntGenerator bigIntGenerator;
    @Autowired
    private RevokedCertificateServiceImpl revokedCertificateService;
    @Autowired
    private KeyExpirationServiceImpl keyExpirationService;
    @Autowired
    private CertificateDBServiceImpl certificateDBService;
    @Autowired
    private RevocationReasonServiceImpl revocationReasonService;

    private KeyPair keyPairSubject = generateKeyPair();
    private X509Certificate cert;
    private X509Certificate issuerCertificate;
    private String fileLocationCA = "keystore/keystoreCA.jks";
    private String fileLocationEE = "keystore/keystoreEE.jks";
    private String passwordCA = "passwordCA";
    private String passwordEE = "passwordEE";

    @Override
    public ArrayList<CertificateBasicDTO> getAllCertificates() throws CertificateEncodingException {

        ArrayList<CertificateBasicDTO> certificateBasicDTOS = new ArrayList<>();
        //Reading all CA
        Enumeration<String> aliases = store.getAllAliases(fileLocationCA, passwordCA);
        if(aliases != null) {
            while (aliases.hasMoreElements()) {
                Certificate c = store.findCertificateByAlias(aliases.nextElement(), fileLocationCA, passwordCA);
                JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) c);
                certificateBasicDTOS.add(new CertificateBasicDTO(certHolder));

            }
        }

        //Reading all end-entity
        aliases = store.getAllAliases(fileLocationEE, passwordEE);
        if(aliases != null) {
            while (aliases.hasMoreElements()) {
                Certificate c = store.findCertificateByAlias(aliases.nextElement(), fileLocationEE, passwordEE);
                JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) c);
                certificateBasicDTOS.add(new CertificateBasicDTO(certHolder));

            }
        }
        return certificateBasicDTOS;
    }

    @Override
    public CertificateDetailsDTO getCertificateDetails(String serialNumber) throws CertificateEncodingException, CertificateParsingException {

        CertificateDB certDB = certificateDBService.findCertificate(serialNumber);
        X509Certificate cert;
        if(certDB.isCa()) {
            cert = (X509Certificate) store.findCertificateBySerialNumber(serialNumber, fileLocationCA, passwordCA);
            if(cert != null) {
                JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) cert);
                Certificate[] chain = store.findCertificateChainBySerialNumber(serialNumber, fileLocationCA, passwordCA);
                X509Certificate x509Cert;
                Boolean isRoot;
                if (chain.length == 1) { //if it is root then it doesn't have a parent
                    x509Cert = (X509Certificate) chain[0];
                    isRoot = true;
                } else {
                    x509Cert = (X509Certificate) chain[1];
                    isRoot = false;
                }

                String issuerSerialNumber = x509Cert.getSerialNumber().toString();

                CertificateDetailsDTO cddto = new CertificateDetailsDTO(certHolder, cert, issuerSerialNumber, isRoot);
                return cddto;
            }else{
                return null;
            }

        }else{
            cert = (X509Certificate) store.findCertificateBySerialNumber(serialNumber, fileLocationEE, passwordEE);
            if(cert != null) {
                JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) cert);
                String issuerSerialNumber = certDB.getIssuerSerialNumber();
                boolean isRoot = false;
                CertificateDetailsDTO cddto = new CertificateDetailsDTO(certHolder, cert, issuerSerialNumber, isRoot);
                return cddto;
            }else{
                return null;
            }

        }

    }


    @Override
    public boolean addNewCertificate(CertificateDTO certificateDTO) throws CertificateEncodingException {
        keyPairSubject = generateKeyPair();
        SubjectData subjectData = generateSubjectData(certificateDTO);

        if (certificateDTO.getCertificateType().equals(CertificateType.SELF_SIGNED)) {
            issuerCertificate = null;
            IssuerData issuerData = generateIssuerData(certificateDTO);
            cert = certificateGenerator.generateCertificate(subjectData, issuerData, certificateDTO);

        } else if (certificateDTO.getCertificateType().equals(CertificateType.INTERMEDIATE)) {

            String serialNumber = certificateDTO.getIssuerSerialNumber();
            IssuerData issuerData = store.findIssuerBySerialNumber(serialNumber, fileLocationCA, passwordCA);
            issuerCertificate = (X509Certificate) store.findCertificateBySerialNumber(serialNumber, fileLocationCA, passwordCA);
            cert = certificateGenerator.generateCertificate(subjectData, issuerData, certificateDTO);

        } else if (certificateDTO.getCertificateType().equals(CertificateType.END_ENTITY)) {

            String serialNumber = certificateDTO.getIssuerSerialNumber();
            IssuerData issuerData = store.findIssuerBySerialNumber(serialNumber, fileLocationCA, passwordCA);
            issuerCertificate = (X509Certificate) store.findCertificateBySerialNumber(serialNumber, fileLocationCA, passwordCA);
            cert = certificateGenerator.generateCertificate(subjectData, issuerData,
                    certificateDTO);
        }

        if (cert == null) {
            return false;
        }

        if (certificateDTO.getCertificateType().equals(CertificateType.SELF_SIGNED)) {
            keyExpirationService.save(cert);
            store.saveCertificate(new X509Certificate[]{cert}, keyPairSubject.getPrivate(), fileLocationCA, passwordCA);
            //save in the datebase
            CertificateDB certDB = new CertificateDB(cert.getSerialNumber().toString(),null,true);
            certificateDBService.save(certDB);
            System.out.println("******** SAVED ROOT ********");
        }

        if (certificateDTO.getCertificateType().equals(CertificateType.INTERMEDIATE)) {
            Certificate[] issuerChain = store.findCertificateChainBySerialNumber(certificateDTO.getIssuerSerialNumber(), fileLocationCA, passwordCA);
            X509Certificate issuerChainX509[] = new X509Certificate[issuerChain.length + 1];
            issuerChainX509[0] = cert;
            for(int i=0;i<issuerChain.length;i++){
                issuerChainX509[i+1] = (X509Certificate) issuerChain[i];
            }

            //  remember when the key expires for the certificate
            keyExpirationService.save(issuerChainX509[0]);

            store.saveCertificate(issuerChainX509, keyPairSubject.getPrivate(), fileLocationCA, passwordCA);
            //save in the database
            CertificateDB certDB = new CertificateDB(cert.getSerialNumber().toString(),certificateDTO.getIssuerSerialNumber(),true);
            certificateDBService.save(certDB);
            System.out.println("********SAVED INTERMEDIATE********");
        }

        if (certificateDTO.getCertificateType().equals(CertificateType.END_ENTITY)) {
            keyExpirationService.save(cert);
            store.saveCertificate(new X509Certificate[]{cert}, keyPairSubject.getPrivate(), fileLocationEE, passwordEE);
            //save in the database
            CertificateDB certDB = new CertificateDB(cert.getSerialNumber().toString(),certificateDTO.getIssuerSerialNumber(),false);
            certificateDBService.save(certDB);
            System.out.println("******** SAVED END-ENTITY ********");

        }

        return true;
    }

    @Override
    public List<IssuerDTO> getAllCA() throws CertificateEncodingException {

        Enumeration<String> alisases = store.getAllAliases(fileLocationCA, passwordCA);
        List<IssuerDTO> issuerDTOS = new ArrayList<>();

        while (alisases.hasMoreElements()) {
            Certificate c = store.findCertificateByAlias(alisases.nextElement(), fileLocationCA, passwordCA);
            JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) c);
            if (((X509Certificate) c).getBasicConstraints() > -1) {
                if(checkValidityStatus(((X509Certificate) c).getSerialNumber().toString())){
                    issuerDTOS.add(new IssuerDTO(certHolder));
                }
            }
        }
        return issuerDTOS;
    }

    @Override
    public String getAKI(String serialNumber) {

        X509Certificate cert = (X509Certificate) store.findCertificateBySerialNumber(serialNumber, fileLocationCA, passwordCA);
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14");
        byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
        String keyIdentifierHex = new String(Hex.encode(keyIdentifier));
        return keyIdentifierHex;
    }


    @Override
    public byte[] getCertificateDownload(String serialNumber) throws CertificateEncodingException {
        CertificateDB certDB = certificateDBService.findCertificate(serialNumber);
        X509Certificate x509Cert;
        if(certDB.isCa()){
            x509Cert = (X509Certificate) store.findCertificateBySerialNumber(serialNumber,fileLocationCA, passwordCA);
        }else{
            x509Cert = (X509Certificate) store.findCertificateBySerialNumber(serialNumber,fileLocationEE, passwordEE);
        }

        return Base64.getEncoder().encode(x509Cert.getEncoded());
    }

    @Override
    public boolean revokeCertificate(RevokedCertificateDTO revokedCertificateDTO) {
        boolean revoked = this.checkRevocationStatusOCSP(revokedCertificateDTO.getSerialNumber());
        if(revoked){
            return true;
        }
        RevocationReason revocationReason = revocationReasonService.findOne(revokedCertificateDTO.getIdRevocationReason());
        CertificateDB certDB = certificateDBService.findCertificate(revokedCertificateDTO.getSerialNumber());
        //first we revoke the one that we are actually revoking
        certDB.setRevocationReason(revocationReason);
        certDB.setRevoked(true);
        certificateDBService.save(certDB);
        //if it is not end-entity then we revoke all under it
        if(certDB.isCa()){ //if it is ent-entity then we don't revoke further
            revokeChildren(revokedCertificateDTO.getSerialNumber());
        }
        return false;
    }

    private void revokeChildren(String serialNumber){
        ArrayList<CertificateDB> certsDB = (ArrayList<CertificateDB>) certificateDBService.findAllFirstChildren(serialNumber);
        for(CertificateDB certDB: certsDB){
            certDB.setRevoked(true);
            certificateDBService.save(certDB);
            revokeChildren(certDB.getSubjectSerialNumber());
        }
    }

    @Override
    public boolean checkRevocationStatusOCSP(String serialNumber) {
        CertificateDB certDB = certificateDBService.findCertificate(serialNumber);

        //if there are no certificates in the database
        if(certDB == null){
            return true;
        }

        if(certDB.isRevoked()){
            return true;
        }else{
            return false;
        }
    }

    @Override
    public boolean checkValidityStatus(String serialNumber) {

        ArrayList<Certificate> chain = new ArrayList<>();
        CertificateDB cDB = certificateDBService.findCertificate(serialNumber);

        //if there are no certificates in the database
        if(cDB == null){
            return false;
        }

        if(!cDB.isCa()){
            //if it is end-entity we add it in the array and then we take the whole chain of its CA and add that chain in the array
            Certificate cert = store.findCertificateBySerialNumber(serialNumber, fileLocationEE,passwordEE);
            chain.add(cert);
            Certificate[] CAchain = store.findCertificateChainBySerialNumber(cDB.getIssuerSerialNumber(), fileLocationCA,passwordCA);
            for(Certificate c: CAchain) {
                chain.add(c);
            }

        }else{
            //if it is CA then we take its chain and add it in the array
            Certificate[] CAchain = store.findCertificateChainBySerialNumber(serialNumber, fileLocationCA,passwordCA);
            for(Certificate c: CAchain) {
                chain.add(c);
            }

        }

        for(int i =0 ; i < chain.size(); i++) {

            X509Certificate x509Cert = (X509Certificate)chain.get(i);
            X509Certificate x509CACert =null;

            if(i != chain.size()-1) {
                x509CACert = (X509Certificate)chain.get(i+1);
            }else {
                x509CACert = (X509Certificate)chain.get(i); //at the end check the self-signed
            }


            //for every certificate in the chain check whether it expired
            try {
                x509Cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                // TODO Auto-generated catch block
                System.out.println("CERTIFICATE: "+x509Cert.getSerialNumber()+" EXPIRED.");
                e.printStackTrace();
                return false;
            }


            //signature check
            try {
                x509Cert.verify(x509CACert.getPublicKey());
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
                    | SignatureException e) {
                System.out.println("CERTIFICATE: "+x509Cert.getSerialNumber()+" DOESN'T HAVE VALID SIGNATURE.");

                // TODO Auto-generated catch block
                e.printStackTrace();
                return false;

            }

            //check if it's revoked
            if(checkRevocationStatusOCSP(x509Cert.getSerialNumber().toString())) {
                System.out.println("CERTIFICATE: "+x509Cert.getSerialNumber()+" IS REVOKED.");
                return false;
            }

            //check if the issuer is CA
            if(x509CACert.getBasicConstraints() == -1) {
                System.out.println("CERTIFICATE: "+x509CACert.getSerialNumber()+" IS NOT CA.");
                return false;
            }

            //check the key
            if(keyExpirationService.expired(x509Cert.getSerialNumber().toString())) {
                System.out.println("CERTIFICATE'S: "+x509Cert.getSerialNumber()+" KEY EXPIRED.");
                return false;
            }

        }

        System.out.println("CERTIFICATE AND ITS CHAIN ARE VALID.");
        return true;
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SubjectData generateSubjectData(CertificateDTO certificateDTO) {
        try {

            SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = iso8601Formater.parse(certificateDTO.getStartDate());
            Date endDate = iso8601Formater.parse(certificateDTO.getEndDate());

            String serialNumber = bigIntGenerator.generateRandom().toString();

            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            if(!certificateDTO.getSubjectCommonName().equals("")) {
                builder.addRDN(BCStyle.CN, certificateDTO.getSubjectCommonName());
            }
            if(!certificateDTO.getSubjectLastName().equals("")) {
                builder.addRDN(BCStyle.SURNAME, certificateDTO.getSubjectLastName());
            }
            if(!certificateDTO.getSubjectFirstName().equals("")) {
                builder.addRDN(BCStyle.GIVENNAME, certificateDTO.getSubjectFirstName());
            }
            if(!certificateDTO.getSubjectOrganization().equals("")) {
                builder.addRDN(BCStyle.O, certificateDTO.getSubjectOrganization());
            }
            if(!certificateDTO.getSubjectOrganizationUnit().equals("")) {
                builder.addRDN(BCStyle.OU, certificateDTO.getSubjectOrganizationUnit());
            }
            if(!certificateDTO.getSubjectState().equals("")){
                builder.addRDN(BCStyle.ST, certificateDTO.getSubjectState());
            }
            if(!certificateDTO.getSubjectCountry().equals("")) {
                builder.addRDN(BCStyle.C, certificateDTO.getSubjectCountry());
            }
            if(!certificateDTO.getSubjectEmail().equals("")) {
                builder.addRDN(BCStyle.E, certificateDTO.getSubjectEmail());
            }

            return new SubjectData(keyPairSubject.getPublic(), builder.build(), serialNumber, startDate, endDate);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }

    private IssuerData generateIssuerData(CertificateDTO certificateDTO) {
        try {
            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            if(!certificateDTO.getSubjectCommonName().equals("")) {
                builder.addRDN(BCStyle.CN, certificateDTO.getSubjectCommonName());
            }
            if(!certificateDTO.getSubjectLastName().equals("")) {
                builder.addRDN(BCStyle.SURNAME, certificateDTO.getSubjectLastName());
            }
            if(!certificateDTO.getSubjectFirstName().equals("")) {
                builder.addRDN(BCStyle.GIVENNAME, certificateDTO.getSubjectFirstName());
            }
            if(!certificateDTO.getSubjectOrganization().equals("")) {
                builder.addRDN(BCStyle.O, certificateDTO.getSubjectOrganization());
            }
            if(!certificateDTO.getSubjectOrganizationUnit().equals("")) {
                builder.addRDN(BCStyle.OU, certificateDTO.getSubjectOrganizationUnit());
            }
            if(!certificateDTO.getSubjectState().equals("")){
                builder.addRDN(BCStyle.ST, certificateDTO.getSubjectState());
            }
            if(!certificateDTO.getSubjectCountry().equals("")) {
                builder.addRDN(BCStyle.C, certificateDTO.getSubjectCountry());
            }
            if(!certificateDTO.getSubjectEmail().equals("")) {
                builder.addRDN(BCStyle.E, certificateDTO.getSubjectEmail());
            }

            return new IssuerData(keyPairSubject.getPrivate(), builder.build());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
