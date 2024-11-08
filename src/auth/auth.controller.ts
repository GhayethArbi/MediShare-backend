/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-var */
/* eslint-disable @typescript-eslint/no-unused-expressions */
import {Get, Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-tokens.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { VerifyOtpDto } from './dtos/verify-otp.dto';
import { GoogleAuthGuard } from './google-auth.guard';
import { userInfo } from 'os';
import { log } from 'console';
import {UpdateUserIndoDto} from './dtos/update-userInfo.dto'


interface AuthRequest extends Request {
  user?: any; // Define `user` based on what GoogleAuthGuard attaches
}
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }

  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto.refreshToken);
  }

  @Put('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req,
  ) {
    return this.authService.changePassword(
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
      changePasswordDto.userId,

    );
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('verify-otp')
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
    const { recoveryCode } = verifyOtpDto;

    // Call the service to verify the OTP and get the reset token
    const result = await this.authService.verifyOtp(recoveryCode);
    return result; // Returns the reset token
   
  }
 

  @Put('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const { newPassword, resetToken } = resetPasswordDto;

    // Call the service to reset the password
   
      const result = await this.authService.resetPassword(newPassword, resetToken);
      return result; // Success message after password reset
    
  }


  // Google login initiation
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleLogin() {
    // Initiates the Google OAuth flow
  }

  // Google login redirect
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleLoginRedirect(@Req() req: AuthRequest) { // Use AuthRequest to access req.user
  
   var userDto = new LoginDto()
   userDto.email = req.user.email
   userDto.password = req.user.password
   
    return this.authService.loginGoogle(req.user)
    //this.authService.login(userDto) // Log in the user
  
  }





















  @Put('update-user')
  async upadteUserInfo(@Body() updateuserinfo: UpdateUserIndoDto) {

    // Call the service to reset the password
   var email = updateuserinfo.email ; 
   var name1 = updateuserinfo.name;
  var  userId = updateuserinfo.userId;

      const result = await this.authService.upadetuserInformation(name1,email,userId);
      return result; // Success message after password reset
    
  }



}
