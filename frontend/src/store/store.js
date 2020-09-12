import Vue from 'vue'
import Vuex from 'vuex'
import axios from 'axios'

Vue.use(Vuex)

export const store =  new Vuex.Store({
    state: {
        token: localStorage.getItem("access_token") || null
            
    },
    getters:{
        loggedIn(state){
            return state.token !== null;
        }

    },
    mutations:{
        retrievedToken(state, token){
            state.token = token;
        },
        destroyedToken(state){
            state.token = null;
        }
    },
    actions:{
        retrieveToken(context, credentials){
            return new Promise((resolve, reject) => {
                axios.post('https://localhost:9000/auth/login',{
                    email: credentials.email,
                    password: credentials.password
                })
                .then(response => {
                    const token = response.data.accessToken;
                    localStorage.setItem("access_token", token);
                    context.commit('retrievedToken', token);
                    resolve(response);
                })
                .catch(error => {
                    console.log(error);
                    reject(error);
                })
            })
        },
        destroyToken(context){
            localStorage.removeItem("access_token");
            context.commit('destroyedToken');
            console.log("push to login");
        }
    }
})