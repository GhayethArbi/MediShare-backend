import { IsString } from "class-validator";

export class CreateRecommadationDto {

    @IsString()
    title : string
    @IsString()
    userId:string

    @IsString()
    recommendation:string


}
