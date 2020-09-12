<template>
    <div class="container pt-5  justify-content-center" style=" width: 40%">
      <b-card no-body border-variant="dark" bg-variant="light" header="Certificate" align="center" title="Certificate informaton">
        <b-tabs card>
            <b-tab title="General" active>
                <b-card-text>
                    <b-card bg-variant="light" header="Certificate information" align="left" >
                        <b-card-text> <b> Issued to: </b> {{this.certificate.subjectCommonName}}</b-card-text>
                         <b-card-text> <b> Issued by: </b> {{this.certificate.issuerCommonName}}</b-card-text>
                        <b-card-text> <b> Valid from </b> {{this.certificate.startDate}} <b> to </b> {{this.certificate.endDate}}</b-card-text>
                    </b-card>
                </b-card-text>
            </b-tab>
            <b-tab title="Details">
                <b-card-text >
                     <b-card bg-variant="light" align="left" >
                        <b-card-text> <b> Version: </b> {{this.certificate.version}} </b-card-text>
                        <b-card-text> <b> Serial number: </b> {{this.certificate.serialNumber}}</b-card-text>
                        <b-card-text> <b> Signature algorthm: </b> {{this.certificate.signatureAlgorithm}}</b-card-text>
                        <b-card-text> <b> Signature hash algorthm: </b> {{this.certificate.signatureHashAlgorithm}}</b-card-text>
                        <b-button v-b-toggle.collapse-1 variant="outline-primary" >Public key</b-button>
                            <b-collapse  id="collapse-1">
                                <b-card>{{this.certificate.publicKey}}</b-card>
                            </b-collapse>
                    </b-card>
                </b-card-text>
            </b-tab>
            <b-tab title="Extensions">
                <b-card-text >
                     <b-card bg-variant="light" align="left" >
                        <b-card-text> <b> Basic Constraints: </b> Subject type: {{this.certificate.type}}</b-card-text>
                        <b-card-text> <b> Subject Key Identifier: </b>  {{this.certificate.subjectKeyIdentifier}}</b-card-text>
                        <b-card-text v-show="!this.certificate.isRoot"> <b> Authority Key Identifier: </b>  {{this.certificate.authorityKeyIdentifier}}</b-card-text>
                        <b-card-text v-show="this.certificate.subjectAlternativeNames"> <b> Subject Alternative Names: </b> 
                            <b-card-text v-for="san in this.certificate.subjectAlternativeNames" :key="san" > {{san}}  </b-card-text>
                         </b-card-text>
                         <b-card-text v-show="this.certificate.keyUsageList"> <b>  Key Usage: </b>  
                            <b-card-text v-for="ku in this.certificate.keyUsageList" :key="ku" > {{ku}}  </b-card-text>
                        </b-card-text>
                        <b-card-text v-show="this.certificate.extendedKeyUsageList"> <b> Extended Key Usage: </b>  
                            <b-card-text v-for="eku in this.certificate.extendedKeyUsageList" :key="eku" > {{eku}}  </b-card-text>
                        </b-card-text>                    
                        <b-card-text> <b> Authority Information Access: </b>  </b-card-text>
                        <b-button v-b-toggle.collapse-1 variant="outline-primary" @click="checkOCSP()" >Check OCSP status</b-button>

                        <b-alert class="mt-2" :show="this.OCSPTrue" dismissible fade variant="success">Certificate is not revoked.</b-alert>

                        <b-alert class="mt-2" :show="this.OCSPFalse" dismissible fade variant="danger">Certificate is revoked.</b-alert>
                     </b-card>
                </b-card-text>
            </b-tab>

            <b-tab title="Subject">
                <b-card-text >
                     <b-card bg-variant="light" align="left" >
                        <b-card-text v-show="this.certificate.subject"> <b> Subject:  </b> {{this.certificate.subject}} </b-card-text>
                        <b-card-text v-show="this.certificate.subjectGivenname"> <b> Subject Name: </b> {{this.certificate.subjectGivenname}} </b-card-text>
                        <b-card-text v-show="this.certificate.subjectSurname"> <b> Subject Surname: </b> {{this.certificate.subjectSurname}} </b-card-text>
                        <b-card-text v-show="this.certificate.subjectEmail"> <b> Subject Email: </b> {{this.certificate.subjectEmail}} </b-card-text>
                     </b-card>
                </b-card-text>
            </b-tab>
            <b-tab title="Issuer">
                <b-card-text >
                     <b-card bg-variant="light" align="left" >
                        <b-card-text v-show="this.certificate.issuer"> <b> Issuer:  </b> {{this.certificate.issuer}} </b-card-text>
                        <b-card-text v-show="this.certificate.issuerGivenname"> <b> Issuer Name: </b> {{this.certificate.issuerGivenname}} </b-card-text>
                        <b-card-text v-show="this.certificate.issuerSurname"> <b> Issuer Surname: </b> {{this.certificate.issuerSurname}} </b-card-text>
                        <b-card-text v-show="this.certificate.issuerEmail"> <b> Issuer Email: </b> {{this.certificate.issuerEmail}} </b-card-text>
                        <b-button size="sm" variant="outline-primary" v-show="!this.certificate.isRoot" @click="showIssuerCertificate()"  align="center"> Show issuers certificate </b-button>
                     </b-card>
                     
                </b-card-text>
            </b-tab>
          </b-tabs>
          <b-button href="/allCertificates" variant="secondary" style="width: 6em; margin: 1em">Go back </b-button>
        </b-card>
    </div>
</template>

<script>
import axios from "axios";

const baseUrl = "https://localhost:9000/api/pki/";


export default {
    name: "CertificateDetails",
    data() {
    return {
      certificate: {},
      OCSPTrue : false,
      OCSPFalse : false
    }  
  },
  methods: {
        showIssuerCertificate: function()
        {
            this.$router.push({ path: 'certificateDetails', query: { sn: this.certificate.issuerSerialNumber } });
        },
        getIssuerCertificate: function() //calling before route update
        {
            axios.get(baseUrl + "getCertificateDetails/"+this.certificate.issuerSerialNumber).then(
            response=> {
                this.certificate = response.data;
            }
        )
        },
        checkOCSP()
        {
            axios.get("https://localhost:9000/api/pki/checkRevocationStatusOCSP/"+this.certificate.serialNumber).then(
                response => {
                    console.log(response.data)
                    if(response.data==false)
                    {
                        this.OCSPTrue = true;
                        setTimeout(() => {this.OCSPTrue = false;}, 4500);
                    }
                    else
                    {
                        this.OCSPFalse = true;
                        setTimeout(() => {this.OCSPFalse = false;}, 4500 )
                    }
                }
            )
        }
        
    },
    created() {
        var id = this.$route.fullPath;
        id = id.split('?')[1];
        id = id.split('=')[1];
        axios.get(baseUrl + "getCertificateDetails/"+id).then(
            response=> {
                this.certificate = response.data;
            }
        )
              
    },
    
    beforeRouteUpdate(to, from, next)
    {
        this.getIssuerCertificate();
        next();
    }

};
</script>

<style scoped>

</style>