<template >
  <div id="temp">
    <NavBar />
    <div class="container pt-5 d-flex justify-content-center">
      <!-- Revocation modal -->
      <b-modal ref="revocationModal" hide-footer title="Select revocation reason">
        <div class="d-flex text-center justify-content-center">
          <b-form-group label="Reasons">
            <b-form-select v-model="reason" :options="reasons">
              <template v-slot:first>
                <b-form-select-option :value="null" disabled>Select revocation reason</b-form-select-option>
              </template>
            </b-form-select>
          </b-form-group>
        </div>
        <div class="row d-flex justify-content-center">
          <b-button class="mt-3 mr-2 col-3" variant="outline-dark" block @click="hideModal">Close</b-button>
          <b-button class="mt-3 col-3" variant="dark" block @click="revoke">Revoke</b-button>
        </div>
      </b-modal>

      <div class="text-center col">

        <b-alert
        :show="showCreated"
        dismissible
        fade
        variant="success"
        >You succesfully revoked certificate</b-alert>

        <b-alert :show="this.valid" dismissible fade variant="success">Certificate is valid.</b-alert>

        <b-alert :show="this.notValid" dismissible fade variant="danger">Certificate is not valid.</b-alert>

        <b-alert :show="this.alreadyRevoked" dismissible fade variant="danger">Certificate is already revoked. </b-alert>

        <h3 class="mb-2">All certificates</h3>
        <div class="container pt-5 d-flex justify-content-center">
          <b-table striped hover bordered borderless :items="items" :fields="fields">
            <template v-slot:cell(details)="row">
              <b-button size="sm" variant="outline-info" @click="showDetails(row.item.serialNumber)" >Details</b-button>
            </template>
            <template v-slot:cell(revoke)="row">
              <b-button size="sm" variant="outline-danger" @click="showModal(row.item.serialNumber)">Revoke</b-button>
            </template>
            <template v-slot:cell(isValid)="row">
              <b-button size="sm" variant="outline-warning" @click="isValid(row.item.serialNumber)" >Check Validity</b-button>
            </template>
            <template v-slot:cell(download)="row">
              <b-button size="sm" variant="outline-success" @click="download(row.item.serialNumber)" >Download</b-button>
            </template>
          </b-table>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import NavBar from "../components/NavBar.vue";
import axios from "axios";

const baseUrl = "https://localhost:9000/api/";

export default {
  name: "AllCertificates",
  components: {
    NavBar
  },
  data() {
    return {
      fields: [
        "serialNumber",
        "subject",
        "startDate",
        "endDate",
        "revoke",
        "details",
        "isValid",
        "download"
      ],
      items: [],
      reasons: [],
      reason: null,
      revocatioReasonId: null,
      serialNumber: null,
      showCreated: false,
      valid : false,
      notValid: false,
      alreadyRevoked: false
    };
  },
  created() {
    axios.get(baseUrl + "pki/getAllCertificates").then(response => {
      this.items = response.data;
    });

    axios
      .get(baseUrl + "revocationReasons/getAllRevocationReasons")
      .then(response => {
        response.data.forEach(element => {
          this.reasons.push({
            value: element.id,
            text: element.name
          });
        });
      });
  },
  methods: {
    showDetails: function(id)
    {
        this.$router.push({ path: 'certificateDetails', query: { sn: id } });
    },
    isValid: function(id)
    {
      axios.get(baseUrl + "pki/checkValidityStatus/"+id).then(
        response => {
          if(response.data==true)
                    {
                        this.valid = true;
                        setTimeout(() => {this.valid = false;}, 4500);
                    }
                    else
                    {
                        this.notValid = true;
                        setTimeout(() => {this.notValid = false;}, 4500 )
                    }
        }
      )

    },
    showModal: function(sn) {
      this.$refs["revocationModal"].show();
      this.serialNumber = sn;
    },
    hideModal() {
      this.$refs["revocationModal"].hide();
    },
    revoke: function() {
      if (this.reason != null) {
        axios
          .put(baseUrl + "pki/revokeCertificate", {
            serialNumber: this.serialNumber,
            idRevocationReason: this.reason
          })
          .then(() => {
            this.hideModal();
            this.showCreated = true;
            setTimeout(() => {
              this.showCreated = false;
            }, 3500);
            setTimeout(() => {
              location.reload();
            }, 4000);
          })
          .catch(error => {
          if (error.response && error.response.status === 400) {
              this.hideModal();
              this.alreadyRevoked= true;
              setTimeout(() => {this.alreadyRevoked = false;}, 3500);
          }
          });
      }
    },
    download: function(sn){

          console.log(sn);
          axios.get(baseUrl + "pki/downloadCertificate/" + sn).then(response => {
                          console.log(response.data);
                          
                          let FileSaver = require('file-saver');
                          let blob = new Blob([response.data],{type: 'pkix-cert'});
                          console.log(blob.size);
                          FileSaver.saveAs(blob, "certificate.cer");
              
                });
    }
  }
};
</script>

<style scoped>
#temp {
  padding: 0;
  margin: 0;
  width: 100%;
  min-height: 100%;
}
</style>