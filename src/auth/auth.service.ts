import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import mongoose, { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { OTP } from './schemas/o-t-p.schema';
import { MailService } from 'src/services/mail.service';
import { RolesService } from 'src/roles/roles.service';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(OTP.name)
    private OTPModel: Model<OTP>,
    private jwtService: JwtService,
    private mailService: MailService,
    private rolesService: RolesService,
  ) { }

  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;
    //const { email, password, name, roleId } = signupData;

    // Check if email is in use
    const emailInUse = await this.UserModel.findOne({ email });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
  
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Create user document and save in MongoDB
    const createdUser = await this.UserModel.create({
    //  roleId,
      name,
      email,
      password: hashedPassword,
    });
  
    // Return the response with statusCode and user information
    return {
      statusCode: HttpStatus.OK,
      data: createdUser,
    };
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
  
    // Find if user exists by email
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }
  
    // Compare entered password with existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }
  
    // Generate JWT tokens
    const tokens = await this.generateUserTokens(user._id);
  
    // Return response with statusCode and user information
    return {
      statusCode: HttpStatus.OK,
      userId: user._id,
      ...tokens,
    };
  }

  async changePassword(userId, oldPassword: string, newPassword: string) {
    //Find the user
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found...');
    }

    //Compare the old password with the password in DB
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Change user's password
    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();
  }

  async forgotPassword(email: string) {
    //Check that user exists
    const user = await this.UserModel.findOne({ email });

    if (user) {
      //If user exists, generate password reset link
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);

      //const resetToken = nanoid(64);
      await this.OTPModel.create({
        otp: otp,
        userId: user._id,
        expiryDate,
      });
      //Send the link to the user by email
      this.mailService.sendPasswordResetEmail(email, otp);
    }

    return {
      statusCode: HttpStatus.OK,
      message: 'If this user exists, they will receive an email',
    };
    
  }

  async verifyOtp(recoveryCode: string) {
    const otp = await this.OTPModel.findOne({
      otp: recoveryCode,
      expiryDate: { $gte: new Date() },
    });
    if (!otp) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    // Generate temporary token for password reset
    const resetToken = this.jwtService.sign(
      { userId: otp.userId },
      { expiresIn: '10m' } // Set short expiration time for security
    );

    // Delete OTP after successful verification
    await this.OTPModel.deleteOne({ otp: recoveryCode });

    return {statusCode: HttpStatus.OK, resetToken };
  }

  async resetPassword(newPassword: string, resetToken: string) {
    try {
      // Verify reset token and extract user ID
      const payload = this.jwtService.verify(resetToken);
      const userId = payload.userId;

      // Retrieve the user and update password
      const user = await this.UserModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      user.password = await bcrypt.hash(newPassword, 10);
      await user.save();

      return { statusCode: HttpStatus.OK,message: 'Your password has been changed successfully!' };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }



  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Refresh Token is invalid');
    }
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '10h' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      {
        upsert: true,
      },
    );
  }

  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId);

    if (!user) throw new BadRequestException();

    const role = await this.rolesService.getRoleById(user.roleId.toString());
    return role.permissions;
  }
}
