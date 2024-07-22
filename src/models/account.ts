import { AuthMethod } from '.';

export default interface IAccount {
  id: string;
  username: string;
  phoneNumber: number;
  email: string;
  avatar: string;
  role: string;
  defaultUsername: boolean;
  authMethods: AuthMethod[];
  isActive: boolean;
  lastLogin: Date;
  ownerId: string;
  guests: string[];
  firebaseUid: string;
}
