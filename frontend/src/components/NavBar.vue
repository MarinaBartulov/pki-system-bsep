<template>
  <div>
    <b-navbar toggleable="lg" type="dark" variant="dark" class="navbar">
      <b-navbar-toggle target="nav-collapse"></b-navbar-toggle>
      <b-collapse id="nav-collapse" is-nav>
        <b-navbar-nav>
          <b-nav-item v-if="loggedIn" href="/" link-classes="text-light"><b>Home</b></b-nav-item>
          <b-nav-item v-if="loggedIn"  href="/newCertificate" link-classes="text-light"><b>Create Certificate</b></b-nav-item>
          <b-nav-item v-if="loggedIn"  href="/allCertificates" link-classes="text-light"><b>All Certificates</b></b-nav-item>
        </b-navbar-nav>

        <b-collapse id="nav-collapse" is-nav>
        <b-navbar-nav class="ml-auto">
          <b-nav-item v-if="!loggedIn" href="/login" link-classes="text-light"><b>Log in</b></b-nav-item>
          <b-nav-item v-if="loggedIn" @click="logout()" link-classes="text-light"><b>Log out</b></b-nav-item>
        </b-navbar-nav>
      </b-collapse>
      </b-collapse>
    </b-navbar>
  </div>
</template>

<script>

export default {
 
  methods: {
       logout: function() { 
          this.$store.dispatch('destroyToken');
          this.$router.push({'name': 'LoginPage'});
          
       }
    },
    computed: {
      loggedIn(){
        return this.$store.getters.loggedIn;
      }
    }
};
</script>

<style scoped>
.defaultStyle {
  text-decoration: none;
}
</style>