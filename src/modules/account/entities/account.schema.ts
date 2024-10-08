import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { AuthMethod, Role } from 'src/models';
import IAccount from 'src/models/account';

export type AccountDocument = HydratedDocument<IAccount>;

@Schema({
  timestamps: true,
  versionKey: false,
})
export class Account implements Omit<IAccount, 'id'> {
  @Prop()
  lastname: string;

  @Prop()
  firstname: string;

  @Prop({ required: true, unique: true, lowercase: true })
  username: string;

  @Prop()
  phone: number;

  @Prop()
  email: string;

  @Prop()
  avatar: string;

  @Prop()
  birthdate: Date;

  @Prop()
  address: string;

  @Prop({ default: Role.USER })
  role: string;

  @Prop({ default: false })
  defaultUsername: boolean;

  @Prop()
  authMethods: AuthMethod[];

  @Prop()
  password: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  lastLogin: Date;
}

export const AccountSchema = SchemaFactory.createForClass(Account);
