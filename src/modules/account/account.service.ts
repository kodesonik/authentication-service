import { Device } from './entities/device.schema';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  // NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateAccountDto } from './dto/create-account.dto';
import { UpdateAccountDto } from './dto/update-account.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Account } from './entities/account.schema';
import { Model } from 'mongoose';
import RedisService from 'src/services/redis.service';
import { JwtService } from '@nestjs/jwt';
import { IDevice } from 'src/models/device';
import { ConfigService } from '@nestjs/config';
import { AuthMethod } from 'src/models';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ClientProxy } from '@nestjs/microservices';

@Injectable()
export class AccountService {
  constructor(
    @InjectModel(Account.name) private readonly accountModel: Model<Account>,
    @InjectModel(Device.name) private readonly deviceModel: Model<Device>,
    private readonly redisService: RedisService,
    @Inject('MESSAGING_SERVICE')
    private readonly messagingService: ClientProxy,
    // @Inject('USER_SERVICE') private readonly userService: any,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private isEmail(key: string) {
    return key.includes('@');
  }

  private async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async isEmailUnique(email: string): Promise<boolean> {
    //Check if the user email provide is unique
    const response = await this.accountModel.findOne({ email });
    // Logger.log(response, 'isEmailUnique');
    return !response;
  }

  async isUsernameUnique(username: string): Promise<boolean> {
    //Check if the username provide is unique
    const response = await this.accountModel.findOne({ username });

    return !response;
  }

  async isPhoneUnique(phone: string): Promise<boolean> {
    //Check if the user phone provide is unique
    const response = await this.accountModel.findOne({ phone });

    return !response;
  }

  async decodeToken(token: string) {
    try {
      const decripted = this.jwtService.verify(token);
      if (!decripted) throw new BadRequestException('invalid token');
      const account = await this.accountModel.findById(decripted.id);
      if (!account) throw new BadRequestException('account not found');
      // if (!account.isActive)
      //   throw new BadRequestException('account not active');
      return account.toObject();
    } catch (error) {
      Logger.error(error.message, 'DecodeToken');
      return { error: error.message, status: error.status };
    }
  }

  //register
  async register(registerDto: RegisterDto) {
    try {
      //Check if the user email provide is unique
      const isEmailUnique = await this.isEmailUnique(registerDto.email);
      if (!isEmailUnique) {
        throw new BadRequestException('Email already exist');
      }

      //Check if the username provide is unique
      const isUsernameUnique = await this.isUsernameUnique(
        registerDto.username,
      );
      if (!isUsernameUnique) {
        throw new BadRequestException('Username already exist');
      }

      //Check if the user phone provide is unique
      const isPhoneUnique = await this.isPhoneUnique(registerDto.phone);
      if (!isPhoneUnique) {
        throw new BadRequestException('Phone already exist');
      }

      // hash password
      Logger.log(registerDto);
      registerDto.password = await this.hashPassword(registerDto.password);

      // save user in database
      const account = await this.accountModel.create({
        ...registerDto,
        isActive: true,
      });
      Logger.log(account);

      // generate tokens
      const { _id, ...rest } = account.toObject();
      const access_token = await this.jwtService.signAsync(
        { id: _id, ...rest },
        {
          expiresIn: '10m',
        },
      );
      const refresh_token = await this.jwtService.signAsync(
        { id: _id, ...rest },
        {
          expiresIn: '1y',
        },
      );

      // save tokens in redis
      this.redisService.set(access_token, account._id.toString(), 10);
      this.redisService.set(refresh_token, account._id.toString(), 525600);

      // generate otp 6 digit
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      // // save otp in redis
      this.redisService.set(registerDto.email, otp, 10);

      this.messagingService.send(
        { cmd: 'send-mail-otp' },
        {
          to: registerDto.email,
          otp,
        },
      );
      // message: `otp sent to ${registerDto.email}`
      return {
        access_token,
        refresh_token,
        account: rest,
        message: `otp sent to ${registerDto.email}`,
      };
    } catch (error) {
      Logger.error(error.message, 'Register');
      return { error: error.message, status: error.status };
    }
  }

  //login
  async login(loginDto: LoginDto) {
    try {
      // find account with username or email
      const account = await this.accountModel.findOne({
        $or: [{ email: loginDto.username }, { username: loginDto.username }],
      });
      if (!account) throw new BadRequestException('account not found');
      if (!account.isActive)
        throw new BadRequestException('account not active');
      // compare password
      const isValid = await bcrypt.compare(loginDto.password, account.password);
      if (!isValid) throw new BadRequestException('invalid password');
      // generate tokens
      const { _id, ...rest } = account.toObject();
      const access_token = await this.jwtService.signAsync(
        { id: _id, ...rest },
        {
          expiresIn: '10m',
        },
      );
      const refresh_token = await this.jwtService.signAsync(
        { id: _id, ...rest },
        {
          expiresIn: '1y',
        },
      );
      // save tokens in redis
      this.redisService.set(access_token, account._id.toString(), 10);
      this.redisService.set(refresh_token, account._id.toString(), 525600);
      return { access_token, refresh_token, account: rest };
    } catch (error) {
      Logger.error(error.message, 'Login');
      return { error: error.message, status: error.status };
    }
  }

  //old endopoints

  async sendOtp(credential: string, resend: boolean) {
    try {
      // generate otp 6 digit
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      // Logger.log(otp);
      // Logger.log(credential);
      // save otp in redis
      this.redisService.set(credential, otp, 10);
      // send otp to credential
      let mode: 'mail' | 'whatsapp' | 'sms' = this.isEmail(credential)
        ? 'mail'
        : 'whatsapp';
      mode = mode === 'whatsapp' && resend ? 'sms' : mode;
      await this.messagingService.send(
        { cmd: `send-${mode}/otp` },
        {
          to: credential,
          otp,
        },
      );
      // console.log('res', res);
      return { message: `otp sent to ${credential} via ${mode}.` };
    } catch (error) {
      Logger.error(error.message);
      throw new InternalServerErrorException(error.message);
    }
  }

  async verifyOtp(
    credential: string,
    otp: string,
    device: Omit<IDevice, 'isLoggedIn' | 'isActive'>,
  ) {
    const data = await this.redisService.get(credential);
    // Logger.log(data);
    if (!data) throw new ForbiddenException('otp expired');
    if (data !== otp) throw new BadRequestException('invalid otp');
    let account = await this.accountModel.findOne({
      $or: [{ email: credential }, { phone: credential }],
    });
    if (!account) {
      // create account
      const isEmail = credential.includes('@');
      const usernameFirstPart = isEmail ? credential.split('@')[0] : credential;
      const usernameSecondPart = Math.floor(1000 + Math.random() * 9000);
      const username = `${usernameFirstPart}${usernameSecondPart}`;
      const dts = { username, defaultUsername: true, authMethods: [] };
      if (isEmail) {
        dts['email'] = credential;
        dts['authMethods'].push('mail');
      } else {
        dts['phoneNumber'] = credential;
        dts['authMethods'].push('phone');
      }
      // const { doc } = await this.userService.get(
      //   `user/credential/${credential}`,
      //   {},
      // );
      // Logger.log(doc);
      // dts['ownerId'] = doc?._id || null;
      // dts['firebaseUid'] = doc?.firebaseUid || null;
      account = await this.accountModel.create(dts);
    }

    const accountDevices = await this.deviceModel.find({
      accountId: account._id.toString(),
    });

    // Logger.log(account._id.toString());

    let deviceExist = await this.deviceModel.findOne({ id: device.id });
    if (!deviceExist)
      deviceExist = await this.deviceModel.create({
        ...device,
        accountId: account._id.toString(),
      });
    else if (!deviceExist.isActive)
      throw new ForbiddenException('Cannot login with this device');

    // Disconnect all other devices
    const loggedInDevices = accountDevices.filter((d) => d.isLoggedIn);
    const maxLoggedInDevices = this.configService.get(
      'auth.maxLoggedInDevices',
    );
    if (
      loggedInDevices.length &&
      loggedInDevices.length + 1 >= maxLoggedInDevices
    ) {
      // throw new ForbiddenException('Too many devices logged in');
      // logout the first device
      await this.deviceModel.updateOne(
        { id: loggedInDevices[0].id },
        { isLoggedIn: false },
      );
    }

    // Connect device
    await deviceExist.updateOne({ isLoggedIn: true });
    const { _id, ...rest } = account.toObject();
    const access_token = await this.jwtService.signAsync(
      { id: _id, ...rest },
      {
        expiresIn: '10m',
      },
    );
    const refresh_token = await this.jwtService.signAsync(
      { id: _id, ...rest },
      {
        expiresIn: '1y',
      },
    );

    // save refresh and access tokens in redis
    this.redisService.set(refresh_token, deviceExist?.id, 525600);
    this.redisService.set(access_token, deviceExist?.id, 10);

    //Remove Otp from redis
    this.redisService.delete(credential);
    return {
      access_token,
      refresh_token,
      account: rest,
      message: 'otp verified',
    };
  }

  async refreshToken(refresh_token: string) {
    // Check if refresh token exist
    // const deviceId = await this.redisService.get(refresh_token);

    // Check if device is active
    // if (!deviceId) throw new ForbiddenException('invalid refresh token');
    // const device = await this.deviceModel.findOne({ id: deviceId });
    // if (!device) throw new ForbiddenException('device not found');
    // if (!device.isActive) throw new ForbiddenException('device not active');

    // Check if account is active
    const decripted = this.jwtService.verify(refresh_token);
    if (!decripted) throw new BadRequestException('account not found');
    const account = await this.accountModel.findById(decripted.id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');

    // Generate new tokens
    const { _id, ...rest } = account.toObject();
    const access_token = await this.jwtService.signAsync(
      { id: _id, ...rest },
      {
        expiresIn: '10m',
      },
    );

    // save access token in redis
    this.redisService.set(access_token, _id.toString(), 10);
    return {
      access_token,
      refresh_token,
      account: rest,
      message: 'token refreshed',
    };
  }

  async getProfile(id: string) {
    const account = await this.accountModel.findById(id).select('-password');
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');
    // if (!account.ownerId)
    // throw new NotFoundException('Please complete your profile');
    // const { data } = await this.userService.get(`user/${account.ownerId}/`, {});
    console.log(account);
    return { ...account.toObject(), id: account._id };
  }

  async completeProfile(id: string, createAccountDto: any) {
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');
    // if (account.ownerId)
    //   throw new BadRequestException('profile already completed');
    if (createAccountDto.birthDate)
      createAccountDto.birthDate = new Date(createAccountDto.birthDate);
    // const { status, doc } = await this.userService.send(`user`, {
    //   userName: createAccountDto.username,
    //   email: createAccountDto.email,
    //   phoneNumber: createAccountDto.phoneNumber,
    //   birthDate: createAccountDto.birthdate,
    //   firstName: createAccountDto.firstname,
    //   gender: createAccountDto.gender,
    // });
    // Logger.log(doc);
    // if (status !== 'success')
    // throw new InternalServerErrorException('user not created');
    // const user = doc;
    const updateAccountDto = {
      // ownerId: user._id,
    };

    if (
      !account.authMethods.includes(AuthMethod.EMAIL) &&
      createAccountDto.email
    )
      updateAccountDto['email'] = createAccountDto.email;
    if (
      !account.authMethods.includes(AuthMethod.PHONE) &&
      createAccountDto.phoneNumber
    )
      updateAccountDto['phoneNumber'] = createAccountDto.phoneNumber;
    if (createAccountDto.avatar)
      updateAccountDto['avatar'] = createAccountDto.avatar;
    if (account.defaultUsername && createAccountDto.username)
      updateAccountDto['username'] = createAccountDto.username;

    await account.updateOne(updateAccountDto);
    return { message: 'profile completed' };
  }


  findAll() {
    return `This action returns all account`;
  }

  findOne(id: number) {
    return `This action returns a #${id} account`;
  }

  update(id: number, updateAccountDto: UpdateAccountDto) {
    return `This action updates a #${id} account`;
  }

  remove(id: number) {
    return `This action removes a #${id} account`;
  }
}
