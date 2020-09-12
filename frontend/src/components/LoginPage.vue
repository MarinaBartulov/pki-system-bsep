<template>
<div align="center">
      <NavBar/>
  <div class="container marginTop">
    <b-row class="d-flex justify-content-center responsive">
      <b-col class="col-5 md=5">
        <b-card class="shadow">    
            <div class="text-center">
              <h3 class="dark-grey-text mb-2">
                <strong>Log in</strong>
              </h3>
            </div>
          <b-card-body>
            <b-form @submit.prevent="login()">
              <b-input-group class="mb-4 mt-3">
                <b-input-group-prepend is-text>
                  <b-icon icon="person-fill"></b-icon>
                </b-input-group-prepend>
                <b-form-input v-model="email" type="email" required placeholder="Your email"></b-form-input>
              </b-input-group>
              <b-input-group>
                <b-input-group-prepend is-text>
                  <b-icon icon="lock-fill"></b-icon>
                </b-input-group-prepend>
                <b-form-input v-model="password" type="password" required placeholder="Your password"></b-form-input>
              </b-input-group>
              <b-button type="submit" class="mt-4 mb-1 col-12">Log in</b-button>
              <p class="error" v-if="errorLogin">Email or password is incorrect.</p>
            </b-form>
          </b-card-body>
        </b-card>
      </b-col>
    </b-row>
  </div>
</div>
</template>

<script>
import NavBar from '../components/NavBar.vue'
export default {
  name: 'LoginPage',
  components: {
        NavBar
    },
  data() {
    return {
      email: '',
      password: '',
      errorLogin: false
    }    
  },
  methods: {
    login(){
        this.$store.dispatch('retrieveToken',{
          email: this.email,
          password: this.password
        })
        .then(response => {
          console.log(response);
          this.$router.push({ name: 'StartPage'})
        }).catch(error => {
          if (error.response) {
              this.errorLogin = true;
              setTimeout(() => {this.errorLogin = false;}, 3500);
          }
          });
    }
  }
};
</script>

<style scoped>

.marginTop {
    margin-top: 10%;
}

.shadow {
  -webkit-box-shadow: 5px 5px 5px 5px;
    box-shadow: 5px 5px 5px 5px;
}

.error{
  color:red;
}
</style>