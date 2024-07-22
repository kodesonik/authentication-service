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
  @Prop({ required: true, unique: true, lowercase: true })
  username: string;

  @Prop()
  phoneNumber: number;

  @Prop()
  email: string;

  @Prop()
  avatar: string;

  @Prop({ default: Role.USER })
  role: string;

  @Prop({ default: false })
  defaultUsername: boolean;

  @Prop()
  authMethods: AuthMethod[];

  @Prop({
    select: false,
  })
  password: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  lastLogin: Date;
  @Prop()
  ownerId: string;

  @Prop()
  guests: string[];

  @Prop()
  firebaseUid: string;
}

export const AccountSchema = SchemaFactory.createForClass(Account);
