import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
      lowercase: true,
      required: true,
    },
    password: {
      type: String,
      minlength: 6,
      required: true,
    },
  },
  { timestamps: true }
);

//Se agrega un middleware pre-save que se ejecuta antes de guardar un dato 
//en la base de datos.El middleware se encarga de cifrar la contraseña proporcionada por el usuario 
//antes de almacenarla.
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    //Si la contraseña no ha sido modificada, 
    //se llama a la función next() para pasar al siguiente middleware 
    return next();
  }

  try {
    //La función genSalt() genera una sal aleatoria que se utilizará en el 
    //proceso de cifrado de la contraseña. 
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
  } catch (error) {
    return next(error);
  }
});

//método comparePassword, que se utiliza para comparar una contraseña proporcionada con la contraseña almacenada. 
UserSchema.methods.comparePassword = async function (password) {
  try {
    //El método utiliza bcrypt para comparar las contraseñas 
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw new Error(error);
  }
};

export const UserModel = mongoose.model('User', UserSchema);
