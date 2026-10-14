import { Router } from "express";
import userModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateTokens, verifyRefreshToken } from "../utils/auth.js";
import { verifyAccessToken } from "../utils/auth.js";
import { verify } from "jsonwebtoken";

const router = Router();


router.post("/register",async (req,res)=>{

    console.log(req.body);

    const { name, email, passwordHash} = req.body
    const isUserExists = await userModel.findOne({ email })
    console.log("found in DB:", isUserExists)

    if (isUserExists) {
        return res.status(400).json({
            message:"User already exists",
            error:[
                {
                    path: "email",
                    message:"User already exists"
                }
            ] 
        })
    }

    const user = await userModel.create({
        name,
        email,
        passwordHash : await bcrypt.hash(passwordHash,12)

    })

    const { accessToken, refreshToken } = generateTokens({ userId: user._id});

    user.refreshToken = refreshToken
    await user.save()

    res.cookie("refreshToken", refreshToken,{
        httpOnly: true,
    })

    res.status(201).json({
        message:"user register successfully",
        data:{
            user:{
                name:user.name,
                email:user.email,
            },
            accessToken
        
        }
    })
})

/**
 * @GET /api/auth/me
 */

router.get("/me",async (req,res)=>{

    const accessToken  = req.headers.authorization?.split(" ")[ 1 ]

    try {
        const decoded = verifyAccessToken(accessToken)

        const user = await userModel.findById(decoded._id)

        res.status(200).json({
            message: "user fetched successfully",
            data:{
                user:{
                    name: user.name,
                    email: user.email
                }
            }
        })
    } catch (error) {

        return res.status(401).json({
            message:"Unauthorized, Invalid or expired access token",

        })

    }

})

/**
 * @POST /api/auth/refresh
 */

router.post("/refresh",(req,res)=>{
    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
        return res.status(401).json({
            message: "Unauthorized, refresh token not found"
        })
    }

    try {

        const decoded = await verifyRefreshToken(refreshToken)
        const user = await userModel.findById(decoded.id)

    } catch (error) {
        return res.status(401).json({
            message:"Unauthorized, Invalid or expired refresh token"
        })
    }
})

  

export default router;