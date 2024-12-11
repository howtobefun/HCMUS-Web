import { Schema, model } from 'mongoose';
import mongoose from 'mongoose';


const userSchema = new Schema({
    id: { type: mongoose.Types.ObjectId, auto: true, required: true, unique: true },
    name: { type: String, required: true },
    role: { type: String},
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    ban: { type: Boolean, default: false },
    dob: { type: Date},
    createdAt: { type: Date, default: Date.now },
    subscriptionExpiry: { type: Date },
    penName: { type: String },
    category: { type: String },
    gender:{ type: String },
    country: { type: String },
    googleID: {type: String}
});

const User = model('User', userSchema);

export default User;