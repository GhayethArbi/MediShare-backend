/* eslint-disable no-var */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { OCRData } from './OCRData';
import {AuthService} from '../auth/auth.service'
import { User } from '../auth/schemas/user.schema'

@Injectable()
export class OCRService {
  constructor(
    @InjectModel('OCRData') private ocrDataModel: Model<OCRData>,
    private readonly authService: AuthService

  ) {
  }

  // Method to save extracted OCR data associated with a user
  async saveExtractedData(extractedFields: Record<string, any>, userId: string) {
    console.log("Attempting to save the data houssem");

    var a= this.authService.findUserById(userId)
    console.log("-------------------------------------------------------------------------------------------------------")
    try
    { console.log((await a)._id)}
    catch(error)
    {
      console.log(error)
    }   
    console.log("----------------------------------------------------------------------------------")
    if((await a) == null)
    {
      console.log("user not found")
      return {"error":"user not found "}
    }
    // Include the userId in the OCR data
    const ocrData = new this.ocrDataModel({
      ...extractedFields,
      userId: new Types.ObjectId(userId), // Ensuring userId is stored as ObjectId
    });

    console.log(ocrData);
    return ocrData.save();
  }

  // Optional: Method to retrieve OCR data with populated user information
  async getOCRDataWithUser(ocrDataId: string) {
    return this.ocrDataModel
      .findById(ocrDataId)
      .populate('userId') // Populate user details
      .exec();
  }


  async findAllByUserId(userId: string) {
    try
    {
    var user = this.authService.findUserById(userId);
    if (( !user) == null )
{return {"statuscode" : 404 , "message":"user not found "}}
  
    var a = (await user)._id
a= String(a)
console.log("-------------------------------")



    const objectId = new Types.ObjectId(String(a)); // Convert to ObjectId if needed
    console.log(`Searching for documents with userId: ${objectId}`);
    if ((await user) == null )
    {
      return {"status_code":404 ,"message":"user not found"}
    }
    const results = await this.ocrDataModel.find({ userId: objectId }).exec();
    console.log('Found documents:', results);
    
    return results;
  }
  catch
  {
    return {"message":"user not found or there is another error "}
  }
  }
  
  async getImageDetail(ocrDataId: string) {
    return this.ocrDataModel
      .findById(ocrDataId)
      .exec();
  }

}
