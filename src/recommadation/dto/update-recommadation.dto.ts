import { PartialType } from '@nestjs/mapped-types';
import { CreateRecommadationDto } from './create-recommadation.dto';

export class UpdateRecommadationDto extends PartialType(CreateRecommadationDto) {}
