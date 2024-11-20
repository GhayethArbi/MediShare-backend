/* eslint-disable @typescript-eslint/no-unused-vars */
import { Module } from '@nestjs/common';
import { OCRService } from './ocr.service';
import { MongooseModule } from '@nestjs/mongoose';
import { OCRDataSchema } from './entities/ocr.entity';
import {OCRServiceextraction } from './ocrextraction'
import {FileUploadController} from './UploadService'
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'OCRData', schema: OCRDataSchema }]),AuthModule
     // Register OCRData model
  ],
  controllers: [FileUploadController],
  providers: [OCRService, OCRServiceextraction],
})
export class OcrModule {}
