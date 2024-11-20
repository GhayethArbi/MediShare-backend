import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RolesModule } from './roles/roles.module';
import config from './config/config';
import { MailService } from './services/mail.service';
import { OcrModule } from './ocr/ocr.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';
import { RecommadationModule } from './recommadation/recommadation.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [config],
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config) => ({
        secret: config.get('jwt.secret'),
      }),
      global: true,
      inject: [ConfigService],
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config) => ({
        uri: config.get('database.connectionString'),
      }),
      inject: [ConfigService],
    }),ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'upload'), // Adjusted to point to the root-level uploads folder
      serveRoot: '/upload', // URL prefix to access the images
    }),
    AuthModule,
    RolesModule,
    OcrModule,
    RecommadationModule,

  ],
  controllers: [AppController],
  providers: [AppService, MailService],
})
export class AppModule {}
