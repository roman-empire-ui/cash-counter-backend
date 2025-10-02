import express from 'express'
import { login, resetPassword, signin } from '../controllers/userCon.js'
import  AuthUser from '../middlewares/Auth.js'


const app = express.Router()



app.post('/signin' , signin)
app.post('/login' ,  login)
app.post('/resetPassword' , resetPassword)


export default app;