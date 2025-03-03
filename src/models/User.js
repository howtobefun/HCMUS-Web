import { Schema, model } from 'mongoose';
import mongoose from 'mongoose';

const userSchema = new Schema({
    id: { type: mongoose.Types.ObjectId, auto: true, required: true, unique: true },
    name: { type: String, required: true },
    role: { type: String },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    ban: { type: Boolean, default: false },
    dob: { type: Date },
    createdAt: { type: Date, default: Date.now },
    subscriptionExpiry: { type: Number },
    penName: { type: String },
    category: { type: String },
    googleID: {type: String},
    country : {type: String},
    fullName : {type: String}, 
    gender : {type: String},
    phone : {type: String},
    verified : {type : Boolean, default: false}
});

const User = model('User', userSchema);

export default User;