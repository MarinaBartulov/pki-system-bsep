<template>
<div id="div">
        <NavBar />
<div class="nav-div">
    <h4 class="h4-temp">Templates:</h4>
  <b-nav vertical class="nav-b">
    <b-nav-item @click="RootCACertificate()"><b-button class="w-100" :pressed="tempRootCA"> Root CA Certificate </b-button></b-nav-item>
    <b-nav-item @click="CACertificate()"><b-button class="w-100" :pressed="tempCA"> Intermediate CA Certificate </b-button></b-nav-item>
    <b-nav-item @click="CSCertificate()"><b-button class="w-100" :pressed="tempCS"> CodeSigning Certificate </b-button></b-nav-item>
    <b-nav-item @click="SACertificate()"><b-button class="w-100" :pressed="tempSA"> Server&amp;ClientAuth Certificate </b-button></b-nav-item>
    <b-nav-item @click="OCSPCertificate()"><b-button class="w-100" :pressed="tempOCSP"> OCSPSigning Certificate </b-button></b-nav-item>
  </b-nav>
</div>

<div class="cert-div">
    <h3 class="h4-temp">{{templateName}}</h3>
    <b-form v-if="showForm" @submit.prevent="submit">
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="Version:" label-for="input-version">
            <b-form-input id="input-version" size="sm" disabled v-model="version"></b-form-input>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="6" label-size="sm" label="Signature algorithm" label-for="input-sigAlgor">
            <b-form-input id="sigAlgor" size="sm" disabled v-model="sigAlgorithm"></b-form-input>
           </b-form-group>
        </div>
    </div>
    <hr>
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="2" label-size="sm" label="CN:" label-for="input-CN">
            <b-form-input id="input-CN" size="sm" placeholder="Common name" v-model="subjectCN" required trim></b-form-input>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="4" label-size="sm" label="GIVENNAME:" label-for="input-GIVENANEM">
            <b-form-input id="input-GIVENNAME" size="sm" placeholder="Given name" v-model="subjectGIVENNAME" trim></b-form-input>
           </b-form-group>
        </div>
    </div> 
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="SURNAME:" label-for="input-SURNAME">
            <b-form-input id="input-SURNAME" size="sm" placeholder="Surname" v-model="subjectSURNAME" trim></b-form-input>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="1" label-size="sm" label="O:" label-for="input-O">
            <b-form-input id="input-O" size="sm" placeholder="Organization" v-model="subjectO" trim></b-form-input>
           </b-form-group>
        </div>
    </div> 
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="2" label-size="sm" label="OU:" label-for="input-OU">
            <b-form-input id="input-OU" size="sm" placeholder="Organzation unit" v-model="subjectOU" trim></b-form-input>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="1" label-size="sm" label="C:" label-for="input-C">
            <b-form-input id="input-C" size="sm" placeholder="Country" v-model="subjectC" trim></b-form-input>
           </b-form-group>
        </div>
    </div>
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="2" label-size="sm" label="ST:" label-for="input-ST">
              <b-form-input id="input-ST" size="sm" placeholder="State or province" v-model="subjectST" trim></b-form-input>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="1" label-size="sm" label="E:" label-for="input-E">
              <b-form-input type="email" id="input-E" size="sm" placeholder="Email" v-model="subjectE" trim></b-form-input>
           </b-form-group>
        </div>
    </div>
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="3" label-size="sm" label="Valid from:">
              <b-form-datepicker size="sm" :min="minDate" v-model="startDate" locale="en" placeholder="Start date"></b-form-datepicker>
            </b-form-group> 
        </div>
        <div class="col">
            <b-form-group label-cols="1" label-cols-lg="3" label-size="sm" label="Valid to:">
              <b-form-datepicker size="sm" :min="minDate" :max="maxDate"  v-model="endDate" locale="en" placeholder="End date"></b-form-datepicker>
           </b-form-group>
        </div>
    </div>
    <div v-if="!tempRootCA" class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="2" label-size="sm" label="Issuer:">
              <b-form-select size="sm" text="Issuer" v-model="issuer" :options="issuers">
                <template v-slot:first>
                  <b-form-select-option :value="null" disabled>Select an issuer</b-form-select-option>
                </template>
              </b-form-select>            
            </b-form-group> 
        </div>
    </div>
     <hr>
    <div v-if="!tempRootCA" class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="Authority Key Identifier:" label-for="input-AKI">
            <b-form-input id="input-AKI" size="sm" disabled v-model="authKeyIdentifier"></b-form-input>     
            </b-form-group> 
        </div>
    </div>
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="Basic Constraints:" label-for="input-sm">
            <b-form-input id="input-sm" size="sm" disabled v-model="basicC"></b-form-input>     
            </b-form-group> 
        </div>
    </div>
    <div class="containter mx-2 row">
        <div class="col-6">
            <b-form-group  label-cols="2" label-cols-lg="7" label-size="sm" label="Subject Alternative Name:">
              <b-form-select size="sm" text="Type" v-model="typeSAN" :options="typesSAN">
                <template v-slot:first>
                  <b-form-select-option :value="null">Select type</b-form-select-option>
                </template>
              </b-form-select>            
            </b-form-group> 
        </div>
        <div class="col-6">
            <b-form-group label-cols-lg="1" label-size="sm" label-for="input-san" :invalid-feedback="invalidFeedbackSAN" :valid-feedback="validFeedbackSAN" :state="stateSAN">
            <b-form-input id="input-san" size="sm" :disabled="!selectedTypeSAN" placeholder="Enter a value" v-model="valueSAN" trim></b-form-input>     
            </b-form-group> 
        </div>
    </div>
    <div class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="Key Usage:" label-for="input-keyUsage">
            <b-form-input id="input-keyUsage" size="sm" disabled v-model="keyUsages"></b-form-input>     
            </b-form-group> 
        </div>
    </div>
    <div v-if="!tempRootCA && !tempCA" class="containter mx-2 row">
        <div class="col">
            <b-form-group  label-cols="1" label-cols-lg="4" label-size="sm" label="Extended Key Usage:" label-for="input-eKeyUsage">
            <b-form-input id="input-eKeyUsage" size="sm" disabled v-model="eKeyUsages"></b-form-input>     
            </b-form-group> 
        </div>
    </div>
    <div class="containter mx-2 row text-center">
        <div class="col">
                <b-button type="submit" class="col-5 mt-3 mb-3" :disabled="!isFormValid">Create</b-button>
        </div>
    </div>
    </b-form>
    <b-alert
          :show="showCreated"
          dismissible
          fade
          variant="success"
        >You succesfully created certificate</b-alert>
</div>
<div class="photo-div">
    <img class="img-cert" :src="image" alt="Certificate image"/>

</div>
  </div>
</template>

<script>

import NavBar from "../components/NavBar.vue";
import axios from "axios";
const baseUrl = "https://localhost:9000/api/pki";

//CS
const keyUsageCS = "Digital signature";
const keyUsageCSValue = [128];
const eKeyUsageCS = "Code signing";
const eKeyUsageCSValue = ["1.3.6.5.5.7.3.3"];
const basicConstraintsCS = false;
const bcCSValue = "Subject type = End Entity";
//SA
const keyUsageSA = "Digital signature, Key encipherment";
const keyUsageSAValue = [128, 32];
const eKeyUsageSA = "Server Authentication, Client Authentication";
const eKeyUsageSAValue = ["1.3.6.5.5.7.3.1", "1.3.6.5.5.7.3.2"];
const basicConstraintsSA = false;
const bcSAValue = "Subject type = End Entity";
//OCSP
const keyUsageOCSP = "Digital signature";
const keyUsageOCSPValue = [128];
const eKeyUsageOCSP = "OCSP signing";
const eKeyUsageOCSPValue = ["1.3.6.5.5.7.3.9"];
const basicConstraintsOCSP = false;
const bcOCSPValue = "Subject type = End Entity";

//CA-both
const keyUsageCA = "Digital signature, KeyCert sign, CRL sign";
const keyUsageCAValue = [128, 4, 2];
const basicConstraintsCA = true;
const bcCAValue = "Subject type = CA";


export default {
   name: "NewCertificate",
   components: {
       NavBar
    },
    data() {
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const minD = new Date(today);

        return {
            
            minDate: minD,
            maxDate: null,
            version: "Version 3",
            sigAlgorithm : "sha256RSA",   
            template: "",
            templateName: "Choose a template...",
            image: require('@/assets/certificate.png'),
            tempRootCA: false,
            tempCA: false,
            tempCS: false,
            tempSA: false,
            tempOCSP: false,
            subjectCN: "",
            subjectGIVENNAME: "",
            subjectSURNAME: "",
            subjectO: "",
            subjectOU: "",
            subjectST: "",
            subjectC: "",
            subjectE: "",
            issuer: null,
            startDate: minD,
            endDate: null,
            issuers: [],
            authKeyIdentifier: "",
            basicC: "",
            selectedTypeSAN: false,
            typeSAN: null,
            typesSAN:[
                { value: 2, text: "dNSName"},
                { value: 7, text: "ipAddress"},
                { value: 6, text: "uri"}
            ],
            valueSAN: "",
            keyUsages: "",
            eKeyUsages: "",
            showCreated: false
        }
    },
    methods: {
        RootCACertificate: function(){
            this.template = "RootCA";
            this.templateName = "Root CA Certificate";
            this.tempRootCA = true;
            this.tempCA = false;
            this.tempCS = false;
            this.tempSA = false;
            this.tempOCSP = false;
            this.keyUsages = keyUsageCA;
            this.basicC = bcCAValue;
            this.resetFields();

            
            
        },
        CACertificate: function(){
            this.template = "CA";
            this.templateName = "Intermediate CA Certificate"
            this.tempCA = true;
            this.tempRootCA = false;
            this.tempCS = false;
            this.tempSA = false;
            this.tempOCSP = false;
            this.keyUsages = keyUsageCA;
            this.basicC = bcCAValue;
            this.resetFields();
            
        },
        CSCertificate: function(){
            this.template = "CS";
            this.templateName = "CodeSigning Certificate"
            this.tempCS = true;
            this.tempCA = false;
            this.tempRootCA = false;
            this.tempSA = false;
            this.tempOCSP = false;
            this.keyUsages = keyUsageCS;
            this.eKeyUsages = eKeyUsageCS;
            this.basicC = bcCSValue;
            this.resetFields();

        },
        SACertificate: function(){
            this.template = "SA";
            this.templateName = "Server&ClientAuth Certificate"
            this.tempSA = true;
            this.tempCA = false;
            this.tempRootCA = false;
            this.tempCS = false;
            this.tempOCSP = false;
            this.keyUsages = keyUsageSA;
            this.eKeyUsages = eKeyUsageSA;
            this.basicC = bcSAValue;
            this.resetFields();

        },
        OCSPCertificate: function(){
            this.template = "OCSP";
            this.templateName = "OCSPSigning Certificate"
            this.tempOCSP = true;
            this.tempCS = false;
            this.tempCA = false;
            this.tempRootCA = false;
            this.tempSA = false;
            this.keyUsages = keyUsageOCSP;
            this.eKeyUsages = eKeyUsageOCSP;
            this.basicC = bcOCSPValue;
            this.resetFields();
        },
        resetFields: function() {
            this.subjectCN = "";
            this.subjectGIVENNAME = "";
            this.subjectSURNAME = "";
            this.subjectO = "";
            this.subjectOU = "";
            this.subjectST = "";
            this.subjectC = "";
            this.subjectE = "";
            this.issuer = null;
            this.issuers = [];
            this.authKeyIdentifier = "",
            this.endDate = null;
            this.typeSAN = null;
            this.valueSAN = "";
            let now = new Date();
            let today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            this.startDate = new Date(today);
            if(!this.tempRootCA){
            this.retrieveCAs();
            }
        },
        submit: function(){

            let certDTO = {
                subjectCommonName: this.subjectCN,
                subjectFirstName: this.subjectGIVENNAME,
                subjectLastName: this.subjectSURNAME,
                subjectEmail: this.subjectE,
                subjectOrganization: this.subjectO,
                subjectOrganizationUnit: this.subjectOU,
                subjectState: this.subjectST,
                subjectCountry: this.subjectC,
                startDate: this.startDate,
                endDate: this.endDate,
                issuerSerialNumber: this.issuer
                };

            if(this.typeSAN!=null & this.valueSAN != ""){
                certDTO.typeSAN = this.typeSAN;
                certDTO.valueSAN = this.valueSAN;
            }    

            if(this.template=="RootCA"){
                certDTO.certificateType = 'SELF_SIGNED';
                certDTO.basicConstraints = basicConstraintsCA;
                certDTO.keyUsageList = keyUsageCAValue;

                 
            }else if(this.template=="CA"){
                certDTO.certificateType = 'INTERMEDIATE';
                certDTO.basicConstraints = basicConstraintsCA;
                certDTO.keyUsageList = keyUsageCAValue;

            }else if(this.template=="CS"){
                certDTO.certificateType = 'END_ENTITY';
                certDTO.basicConstraints = basicConstraintsCS;
                certDTO.keyUsageList = keyUsageCSValue;
                certDTO.extendedKeyUsageList = eKeyUsageCSValue;

            }else if(this.template=="SA"){
                certDTO.certificateType = 'END_ENTITY';
                certDTO.basicConstraints = basicConstraintsSA;
                certDTO.keyUsageList = keyUsageSAValue;
                certDTO.extendedKeyUsageList = eKeyUsageSAValue;

            }else if(this.template=="OCSP"){
                certDTO.certificateType = 'END_ENTITY';
                certDTO.basicConstraints = basicConstraintsOCSP;
                certDTO.keyUsageList = keyUsageOCSPValue;
                certDTO.extendedKeyUsageList = eKeyUsageOCSPValue;
            }

            axios.post(baseUrl + "/addNewCertificate", certDTO)
                 .then(() => {
                     this.showCreated = true;
                     setTimeout(() => {this.showCreated = false;}, 3500);
                     this.resetFields();
             });
        },
        retrieveCAs: function(){
                axios.get(baseUrl + "/getAllCA").then(response => {
                    response.data.forEach(element => {
                        console.log(element.serialNumber);
                        this.issuers.push({
        
                            value: element.serialNumber,
                            text: element.commonName
                        });
                    });
                });
        }


    },
    computed: {
        isFormValid: function() {
            
            if(this.tempRootCA){
                return this.subjectCN && this.endDate && this.stateSAN;
            }else{
                return this.subjectCN && this.issuer && this.endDate && this.stateSAN;
            }
    
        },
        showForm: function(){
            return this.tempRootCA || this.tempCA || this.tempCS || this.tempSA || this.tempOCSP;
        },
        stateSAN: function(){
            if(this.typeSAN == 7 && this.valueSAN != ""){
                 if(!this.valueSAN.match(/(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/)){
                return false;
                }else{
                    return true;
                }
            }else{
                return true;
            }
        },
        invalidFeedbackSAN: function(){

            if(this.stateSAN == false){
                  return 'Invalid format for IP address.';
            }else{
                  return '';
            }            
        },
        validFeedbackSAN: function(){
            
               if(this.typeSAN == 7 && this.valueSAN != ""){
                 if(!this.valueSAN.match(/[0-255].[0-255].[0-255].[0-255]/)){
                return '';
                }else{
                    return 'Valid format';
                }
            }else{
                return '';
            }
                
        }
        
    },
    watch: {
        typeSAN: function(newValue, oldValue){
            if(newValue!=null && oldValue==null){
                this.selectedTypeSAN = true;
            }
            if(newValue==null && oldValue!=null){
                this.selectedTypeSAN = false;
                this.valueSAN = "";
            }
        },
        issuer: function(newValue, oldValue){
            console.log(oldValue);
            if(newValue != null){
               axios.get(baseUrl + "/getAKI/" + newValue).then(response => {
                    this.authKeyIdentifier =  response.data;
                    console.log("Nova vrednost je: " + newValue);
                    console.log("AKI je : " + response.data);
             });
            }
        },
        template: function(newValue, oldValue){
            console.log(oldValue);
            let now = new Date();
            if(newValue == "RootCA"){
                  let maxD = new Date(now.getFullYear() + 25, now.getMonth(), now.getDate());
                  this.maxDate = new Date(maxD);
            }else if(newValue == "CA"){
                  let maxD = new Date(now.getFullYear() + 5, now.getMonth(), now.getDate());
                  this.maxDate = new Date(maxD);
            }else if(newValue == "CS" || newValue == "SA" || newValue=="OCSP"){
                  let maxD = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
                  this.maxDate = new Date(maxD);
            }
        }
    }
        
}
</script>

<style>


.nav-b{
    width: 100%;
}

.h4-temp{
    text-align: center;
    margin-bottom: 0.5em;
    margin-top: 0.5em;
}

.nav-div{
    width:18%;
    float:left;
    
}

.cert-div {
    float:left;
    border: 1px solid black;
    width: 50%;
    margin-left:10%;
    margin-top:2em;
    margin-bottom: 3em;
}

.photo-div {
    float:left;
    width: 10%;
    margin-left:3%;
    margin-top:2em;
}

.img-cert{

    width:8em;
    height:8em;
    margin-left: 40%;
}




</style>