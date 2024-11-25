import { Schema, model } from 'mongoose';

const tagSchema = new Schema({
    id: {
        type: Schema.Types.ObjectId, 
        auto: true,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    }
});

const Tag = model('Tag', tagSchema);

export default Tag;
