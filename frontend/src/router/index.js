import Vue from 'vue'
import Router from 'vue-router'
import AllCertificates from '../components/AllCertificates.vue'
import startPage from '../components/startPage.vue'
import CertificateDetails from '../components/CertificateDetails.vue'
import NewCertificate from '../components/NewCertificate.vue'
import LoginPage from '../components/LoginPage.vue'

Vue.use(Router)

export default new Router({
    mode: 'history',
    routes: [
        {
            path: '/',
            name: 'StartPage',
            component: startPage
        },
        {
            path: '/login',
            name: 'LoginPage',
            component: LoginPage
        },
        {
            path: '/allCertificates',
            name: 'AllCertificates',
            component: AllCertificates
        },
        {
            path: '/certificateDetails',
            name: 'CertificateDetails',
            component: CertificateDetails
        },
        {
            path: '/newCertificate',
            name: 'NewCertificate',
            component: NewCertificate
        },
        {
            path: '*',
            redirect: '/'
        }
    ]
})