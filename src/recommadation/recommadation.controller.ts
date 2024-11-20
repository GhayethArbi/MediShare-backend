/* eslint-disable no-var */
import { Controller, Post, Body, InternalServerErrorException } from '@nestjs/common';
import { RecommadationService } from './recommadation.service';
import { CreateRecommadationDto } from './dto/create-recommadation.dto';

@Controller('ai')
export class GoogleAIController {
  constructor(private readonly googleAIService: RecommadationService) {}

  // Extract JSON from a string
  extractJson(input: string): object | null {
    try {
      const startIndex = input.indexOf('{');
      const endIndex = input.lastIndexOf('}');
      if (startIndex !== -1 && endIndex !== -1 && startIndex < endIndex) {
        const jsonString = input.slice(startIndex, endIndex + 1);
        return JSON.parse(jsonString);
      }
      return null;
    } catch (error) {
      console.error('Invalid JSON content:', error);
      return null;
    }
  }

  @Post('generate')
  async generate(@Body('userId') userId: string) {
    try {
      const prompt = `Give me some general recommendations for general health. 
                      I want one recommendation. Try to return JSON that contains 
                      {title: choose a title, recommendation: ...}.
                      The recommendation should be a 1-minute read.`;
      
      const response = await this.googleAIService.generateContent(prompt);
      const cleanJson = this.extractJson(response);

      if (!cleanJson || typeof cleanJson !== 'object' || !cleanJson['title'] || !cleanJson['recommendation']) {
        throw new Error('AI response does not contain valid recommendation data.');
      }

      // Create a recommendation DTO
      const createRecommadationDto: CreateRecommadationDto = {
        userId,
        title: cleanJson['title'],
        recommendation: cleanJson['recommendation'],
      };

      // Save the recommendation in the database
      const savedRecommendation = await this.googleAIService.createRecommadation(
        createRecommadationDto.userId,
        createRecommadationDto.title,
        createRecommadationDto.recommendation,
      );

      return { success: true, data: savedRecommendation };
    } catch (error) {
      console.error('Error generating recommendation:', error.message);
      throw new InternalServerErrorException(error.message);
    }
  }
}
