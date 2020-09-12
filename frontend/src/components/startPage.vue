<template>
    <div id="div">
        <NavBar />
    <div>
    <b-carousel
     id="carousel-1"
      v-model="slide"
      :interval="4000"
      controls
      indicators
      background="#ababab"
      img-width="1024"
      img-height="480"
      style="text-shadow: 1px 1px 2px #333;"
      @sliding-start="onSlideStart"
      @sliding-end="onSlideEnd"
          
    >

      <b-carousel-slide
        caption="Welcome to Public Key Infrastructure System"
        img-src="https://www.thesslstore.com/blog/wp-content/uploads/2018/02/iStock-614137450.jpg"
      ></b-carousel-slide>

      <b-carousel-slide
        caption="Here you can create certificate, check it's validity"
        img-src="https://countuponsecurity.files.wordpress.com/2013/10/digital-key.png"
      ></b-carousel-slide>

        <b-carousel-slide
        caption="Or revoke it"
        img-src="https://cdn.pixabay.com/photo/2018/05/04/15/49/cyber-security-3374252_1280.jpg"
      ></b-carousel-slide>
        
    
    </b-carousel>

    
  </div>
        
    </div>
</template>

<script>
import NavBar from "../components/NavBar.vue";

export default {
    name: "StartPage",
    components: {
       NavBar
    },
    data() {
      return {
        slide: 0,
        sliding: null
      }
    },
    methods: {
      onSlideStart() {
        this.sliding = true
      },
      onSlideEnd() {
        this.sliding = false
      }
    }
    
    
  
};
</script>

<style scoped>
    
</style>