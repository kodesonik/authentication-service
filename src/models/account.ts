import { AuthMethod } from '.';

export default interface IAccount {
  id: string;
  lastname: string;
  firstname: string;
  username: string;
  phone: number;
  email: string;
  avatar: string;
  role: string;
  birthdate: Date;
  address: string;
  defaultUsername: boolean;
  authMethods: AuthMethod[];
  isActive: boolean;
  lastLogin: Date;
}
