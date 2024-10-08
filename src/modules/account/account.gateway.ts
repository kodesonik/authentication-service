import { Controller, UseFilters } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AccountService } from './account.service';
import { CreateAccountDto } from './dto/create-account.dto';
import { UpdateAccountDto } from './dto/update-account.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ExceptionFilter } from 'src/filters/rpc-exception.filter';

@Controller()
@UseFilters(new ExceptionFilter())
export class AccountGateway {
  constructor(private readonly accountService: AccountService) {}

  // ´decode-token
  @MessagePattern({ cmd: 'decode-token' })
  decodeToken(@Payload() data: { token: string }) {
    const { token } = data;
    if (!token) {
      return { error: 'Token is required', status: 400 };
    }
    return this.accountService.decodeToken(token);
  }

  // Refresh token
  @MessagePattern({ cmd: 'refresh-token' })
  refreshToken(@Payload() data: { refresh_token: string }) {
    const { refresh_token } = data;
    if (!refresh_token) {
      return { error: 'Refresh token is required', status: 400 };
    }
    return this.accountService.refreshToken(refresh_token);
  }


  //register
  @MessagePattern({ cmd: 'register' })
  register(@Payload() registerDto: RegisterDto) {
    try {
      return this.accountService.register(registerDto);
    } catch (error) {
      console.log('error', error);
      return { error: error.message, status: error.status };
    }
  }

  //login
  @MessagePattern({ cmd: 'login' })
  login(@Payload() loginDto: LoginDto) {
    try {
      return this.accountService.login(loginDto);
    } catch (error) {
      console.log('error', error);
      return { error: error.message, status: error.status };
    }
  }

  //forgot password
  @MessagePattern({ cmd: 'forgot-password' })
  forgotPassword(@Payload() createAccountDto: CreateAccountDto) {
    // return this.accountService.create(createAccountDto);
  }

  //reset password
  @MessagePattern({ cmd: 'reset-password' })
  resetPassword(@Payload() createAccountDto: CreateAccountDto) {
    // return this.accountService.create(createAccountDto);
  }

  //change password
  @MessagePattern({ cmd: 'change-password' })
  changePassword(@Payload() createAccountDto: CreateAccountDto) {
    // return this.accountService.create(createAccountDto);
  }

  @MessagePattern({ cmd: 'send-otp' })
  verifyPhoneNumber(@Payload() sendOtpDto: SendOtpDto) {
    const { credential } = sendOtpDto;
    return this.accountService.sendOtp(credential, false);
  }

  @MessagePattern({ cmd: 'verify-otp' })
  verifyOtp(@Payload() verifyOtpDto: VerifyOtpDto) {
    const { credential, otp, device } = verifyOtpDto;
    return this.accountService.verifyOtp(credential, otp, device);
  }

  @MessagePattern({ cmd: 'get-profile' })
  getProfile(@Payload() body: { id: string }) {
    const { id } = body;
    return this.accountService.getProfile(id);
  }

  @MessagePattern({ cmd: 'complete-profile' })
  completeProfile(
    @Payload() req,
    @Payload() createAccountDto: CreateAccountDto,
  ) {
    const { id } = req?.user ?? {};
    return this.accountService.completeProfile(id, createAccountDto);
  }

  @MessagePattern({ cmd: 'check-username' })
  checkUsername(@Payload() createAccountDto: CreateAccountDto) {
    // return this.accountService.create(createAccountDto);
  }

  @MessagePattern({ cmd: 'get-accounts' })
  getAccounts() {
    return this.accountService.findAll();
  }

  @MessagePattern({ cmd: 'get-account' })
  getAccount(@Payload() id: string) {
    return this.accountService.findOne(+id);
  }

  @MessagePattern({ cmd: 'update-credentials' })
  updateCredentials(
    @Payload() id: string,
    @Payload() updateAccountDto: UpdateAccountDto,
  ) {
    return this.accountService.update(+id, updateAccountDto);
  }

  @MessagePattern({ cmd: 'delete-account' })
  deleteAccount(@Payload() id: string) {
    return this.accountService.remove(+id);
  }
}
